package task

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// session is one unified exec session: a script (or shell command) running
// with merged stdout/stderr collected into a bounded buffer.
type session struct {
	id       int64
	owner    []byte
	stdin    io.WriteCloser // nil when write_stdin is not allowed
	maxBuf   int
	mu       sync.Mutex
	buf      []byte
	dropped  int
	exited   bool
	exitCode int
	used     time.Time
	cmds     []*exec.Cmd
	killed   bool
	done     chan struct{}
}

func (s *session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	if over := len(s.buf) - s.maxBuf; over > 0 {
		s.dropped += over
		s.buf = append(s.buf[:0], s.buf[over:]...)
	}
	return len(p), nil
}

func (s *session) drain() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, d := string(s.buf), s.dropped
	s.buf, s.dropped = nil, 0
	s.used = time.Now()
	return out, d
}

func (s *session) isExited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exited
}

func (s *session) lastUsed() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

func (s *session) track(c *exec.Cmd) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.killed {
		return false
	}
	s.cmds = append(s.cmds, c)
	return true
}

func (s *session) kill() {
	s.mu.Lock()
	s.killed = true
	cmds := append([]*exec.Cmd(nil), s.cmds...)
	s.mu.Unlock()
	for _, c := range cmds {
		if c.Process != nil {
			killTree(c)
		}
	}
	if s.stdin != nil {
		s.stdin.Close()
	}
}

// startSession launches the plan and registers the session.
func (h *Handler) startSession(owner []byte, p *runPlan, dir string) (*session, error) {
	s := &session{owner: append([]byte(nil), owner...), maxBuf: h.cfg.MaxOutputBytes, used: time.Now(), done: make(chan struct{})}
	var stdinR *os.File
	if p.stdin {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		stdinR, s.stdin = r, w
	}
	env := h.env()
	h.mu.Lock()
	s.id = h.nextID
	h.nextID++
	h.sessions[s.id] = s
	h.mu.Unlock()

	started := make(chan error, 1)
	go func() {
		code := h.runPlan(s, p, dir, env, stdinR, started)
		s.mu.Lock()
		s.exited, s.exitCode = true, code
		s.mu.Unlock()
		if s.stdin != nil {
			s.stdin.Close()
		}
		close(s.done)
	}()
	if err := <-started; err != nil {
		h.mu.Lock()
		delete(h.sessions, s.id)
		h.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// runPlan executes the script; started receives the result of launching the
// first pipeline. It returns the exit code of the last pipeline that ran.
func (h *Handler) runPlan(s *session, p *runPlan, dir string, env []string, stdin *os.File, started chan<- error) int {
	signalled := false
	signal := func(err error) {
		if !signalled {
			signalled = true
			started <- err
		}
	}
	defer signal(nil)
	if p.shell != "" {
		argv := []string{p.shell, "-c", p.cmd}
		if isCmdExe(p.shell) {
			argv = []string{p.shell, "/C", p.cmd}
		}
		code, err := h.runPipeline(s, [][]string{argv}, []string{argv[0]}, dir, env, stdin, func(err error) {
			signal(err)
			if stdin != nil {
				stdin.Close()
			}
		})
		if err != nil {
			return 127
		}
		return code
	}
	idx := 0
	status := 0
	first := true
	for _, chain := range p.script {
		for i, pl := range chain.Pipelines {
			progs := p.programs[idx : idx+len(pl)]
			idx += len(pl)
			if i > 0 {
				op := chain.Ops[i-1]
				if (op == "&&" && status != 0) || (op == "||" && status == 0) {
					continue
				}
			}
			var in *os.File
			var onStart func(error)
			if first {
				in = stdin
				onStart = func(err error) {
					signal(err)
					if stdin != nil {
						stdin.Close() // the child holds its own copy
					}
				}
				first = false
			}
			code, err := h.runPipeline(s, pl, progs, dir, env, in, onStart)
			if err != nil {
				s.Write([]byte(err.Error() + "\n"))
				code = 127
			}
			status = code
		}
	}
	return status
}

// runPipeline starts every command, calls onStart (if non-nil) once they are
// all running or one failed to start, then waits for them.
func (h *Handler) runPipeline(s *session, argvs [][]string, progs []string, dir string, env []string, stdin *os.File, onStart func(error)) (code int, err error) {
	started := false
	defer func() {
		if !started && onStart != nil {
			onStart(err)
		}
	}()
	cmds := make([]*exec.Cmd, len(argvs))
	var closeAfterStart []*os.File
	for i, argv := range argvs {
		c := exec.Command(progs[i], argv[1:]...)
		c.Args[0] = argv[0]
		c.Dir = dir
		c.Env = env
		c.Stderr = s
		setProcAttr(c)
		cmds[i] = c
	}
	if stdin != nil {
		cmds[0].Stdin = stdin
	}
	for i := 0; i < len(cmds)-1; i++ {
		r, w, err := os.Pipe()
		if err != nil {
			return -1, err
		}
		cmds[i].Stdout = w
		cmds[i+1].Stdin = r
		closeAfterStart = append(closeAfterStart, r, w)
	}
	cmds[len(cmds)-1].Stdout = s
	for i, c := range cmds {
		if !s.track(c) {
			return 137, errors.New("session killed")
		}
		if err := c.Start(); err != nil {
			for _, prev := range cmds[:i] {
				killTree(prev)
				prev.Wait()
			}
			for _, f := range closeAfterStart {
				f.Close()
			}
			return -1, err
		}
	}
	for _, f := range closeAfterStart {
		f.Close()
	}
	started = true
	if onStart != nil {
		onStart(nil)
	}
	for i, c := range cmds {
		werr := c.Wait()
		if i == len(cmds)-1 {
			code = exitCode(c, werr)
		}
	}
	return code, nil
}

func exitCode(c *exec.Cmd, err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code
		}
		return 128 + 9
	}
	return -1
}
