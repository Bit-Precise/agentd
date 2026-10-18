package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/controlclient"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/deviceflow"
)

// openBrowser starts the platform URL handler without a shell. Failure is not
// fatal: the user can open the printed URL on any device.
func openBrowser(url string) error {
	cmd := browserCommand(url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

type loginOptions struct {
	noBrowser bool
	replace   bool
}

// login registers this profile with the OAuth 2.0 Device Authorization Grant.
// A person signs in in a browser and chooses the Workspace and whether the
// device runs as themselves or as a Service Account; the resulting short-lived
// access token is exchanged once for independent device credentials and is
// never written to disk. Instructions go to prompt (stderr), results to out.
func login(ctx context.Context, cfg *config.Config, opts loginOptions, out, prompt io.Writer, open func(string) error, flow *deviceflow.Client) error {
	unlock, err := credentials.Lock(cfg.Agent.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	client, err := controlclient.New(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	if _, err := os.Lstat(filepath.Join(cfg.Agent.StateDir, credentials.Filename)); !os.IsNotExist(err) {
		if !opts.replace {
			return errors.New("profile already has credentials; use --replace only after the registration was revoked or expired")
		}
		if err := retireCredentials(ctx, client, cfg.Agent.StateDir, out); err != nil {
			return err
		}
	}
	info, err := client.Instance(ctx)
	if err != nil {
		return fmt.Errorf("read instance information: %w", err)
	}
	device := info.DeviceAuthorization
	if device == nil {
		return errors.New("this instance does not offer agentd login; register with agentd enroll --key-file")
	}
	if _, err := api.ParseURL(device.Issuer, "deviceAuthorization.issuer", false, false, cfg.Transport.AllowHTTP); err != nil {
		return err
	}
	if flow.HTTP == nil {
		flow.HTTP = client.HTTPClient()
	}
	endpoints, err := flow.Discover(ctx, device.Issuer)
	if err != nil {
		return err
	}
	auth, err := flow.Start(ctx, endpoints.DeviceAuthorization, device.ClientID, device.Scope, device.Audience)
	if err != nil {
		return err
	}
	target := auth.VerificationURIComplete
	if target == "" {
		target = auth.VerificationURI
	}
	if !deviceflow.SameOrigin(device.Issuer, target) {
		return errors.New("authorization server returned a verification URL outside its issuer")
	}
	fmt.Fprintf(prompt, "To register this device, open:\n\n  %s\n\nand enter the code %s. Then choose the Workspace %q and whether the device runs as you or as a Service Account.\n", target, auth.UserCode, cfg.Workspace)
	if !opts.noBrowser {
		if err := open(target); err != nil {
			fmt.Fprintln(prompt, "Could not open a browser; open the URL above on any device.")
		}
	}
	// The authorization server does not tell the device about a decline; the
	// code simply expires.
	fmt.Fprintln(prompt, "Waiting for the authorization to complete (press Ctrl+C if you declined it)...")
	token, err := flow.Poll(ctx, endpoints.Token, device.ClientID, auth)
	if err != nil {
		return err
	}
	response, err := client.ExchangeDeviceEnrollment(ctx, token.AccessToken)
	if err != nil {
		return fmt.Errorf("register device: %w", err)
	}
	if err := credentials.Save(cfg.Agent.StateDir, &response.Credentials); err != nil {
		return err
	}
	principal := response.Agent.Principal
	_, err = fmt.Fprintf(out, "Registered %s (%s) in workspace %s as %s %s\n", response.Agent.Name, response.Agent.ID, response.Agent.Workspace, principal.Type, principal.ID)
	return err
}
