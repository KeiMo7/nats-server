// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// AuthzSource identifies the trigger that produced an authorization evaluation.
type AuthzSource string

const (
	AuthzSourceConnect       AuthzSource = "connect_jwt"
	AuthzSourceAccountUpdate AuthzSource = "account_claim_update"
	AuthzSourceUserUpdate    AuthzSource = "user_claim_update"
	AuthzSourceReload        AuthzSource = "config_reload"
	AuthzSourceExternalAuth  AuthzSource = "external_auth"
)

// AuthzTerminationReason is a stable, machine-readable evaluation failure.
type AuthzTerminationReason string

const (
	AuthzTerminationNone             AuthzTerminationReason = ""
	AuthzReasonMalformedClaim        AuthzTerminationReason = "malformed_claim"
	AuthzReasonInvalidSignature      AuthzTerminationReason = "invalid_signature"
	AuthzReasonUntrustedIssuer       AuthzTerminationReason = "untrusted_issuer"
	AuthzReasonSubjectMismatch       AuthzTerminationReason = "subject_mismatch"
	AuthzReasonVersionExpired        AuthzTerminationReason = "version_expired"
	AuthzReasonRevoked               AuthzTerminationReason = "revoked"
	AuthzReasonClaimExpired          AuthzTerminationReason = "claim_expired"
	AuthzReasonAccountUnavailable    AuthzTerminationReason = "account_unavailable"
	AuthzReasonAccountMigrated       AuthzTerminationReason = "account_migrated"
	AuthzReasonUnauthorizedSubmitter AuthzTerminationReason = "unauthorized_submitter"
	AuthzReasonEvaluationUnavailable AuthzTerminationReason = "evaluation_unavailable"
)

// AuthzSubjectDiff contains set differences for one subject permission class.
type AuthzSubjectDiff struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// AuthzResponseDiff describes a change to response permissions.
type AuthzResponseDiff struct {
	Changed        bool          `json:"changed"`
	MaxMsgs        int           `json:"max_msgs,omitempty"`
	Expires        time.Duration `json:"expires,omitempty"`
	MaxMsgsChanged bool          `json:"max_msgs_changed,omitempty"`
	ExpiresChanged bool          `json:"expires_changed,omitempty"`
}

// AuthzPolicyDiff is the single difference representation used by every source.
type AuthzPolicyDiff struct {
	PublishAllow         AuthzSubjectDiff   `json:"publish_allow,omitempty"`
	PublishDeny          AuthzSubjectDiff   `json:"publish_deny,omitempty"`
	SubscribeAllow       AuthzSubjectDiff   `json:"subscribe_allow,omitempty"`
	SubscribeDeny        AuthzSubjectDiff   `json:"subscribe_deny,omitempty"`
	QueueAllow           AuthzSubjectDiff   `json:"queue_allow,omitempty"`
	QueueDeny            AuthzSubjectDiff   `json:"queue_deny,omitempty"`
	Response             *AuthzResponseDiff `json:"response,omitempty"`
	Categories           []string           `json:"categories,omitempty"`
	RemovedSubscriptions int                `json:"removed_subscriptions,omitempty"`
}

// AuthzAuditEvent is emitted for effective and ineffective policy evaluations.
// It intentionally contains no JWT, signature, password, or token material.
type AuthzAuditEvent struct {
	TypedEvent
	Source                AuthzSource            `json:"source"`
	Trigger               AuthzSource            `json:"trigger,omitempty"`
	Account               string                 `json:"account,omitempty"`
	User                  string                 `json:"user,omitempty"`
	AffectedConnections   int                    `json:"affected_connections"`
	AffectedClients       int                    `json:"affected_clients,omitempty"`
	Affected              int                    `json:"affected"`
	ConnectionCount       int                    `json:"connection_count"`
	ClientCount           int                    `json:"client_count,omitempty"`
	Count                 int                    `json:"count,omitempty"`
	AffectedCount         int                    `json:"affected_count,omitempty"`
	NumAffected           int                    `json:"num_affected,omitempty"`
	Diff                  *AuthzPolicyDiff       `json:"diff,omitempty"`
	DiffCategories        []string               `json:"diff_categories,omitempty"`
	Categories            []string               `json:"categories,omitempty"`
	Reason                AuthzTerminationReason `json:"reason,omitempty"`
	TerminationReason     AuthzTerminationReason `json:"termination_reason,omitempty"`
	Effective             bool                   `json:"effective"`
	Applied               bool                   `json:"applied"`
	Terminated            bool                   `json:"terminated,omitempty"`
	TerminatedConnections int                    `json:"terminated_connections,omitempty"`
	Error                 string                 `json:"error,omitempty"`
	ServerID              string                 `json:"server_id,omitempty"`
}

// AuthzUserClaimBatchResponse reports per-claim outcomes without rolling back
// successful claims when another claim in the same request fails.
type AuthzUserClaimBatchResponse struct {
	Server  *ServerInfo        `json:"server,omitempty"`
	Results []*AuthzAuditEvent `json:"results"`
}

const (
	authzAuditEventType       = "io.nats.server.advisory.v1.auth_policy_update"
	authzAuditEventSubj       = "$SYS.ACCOUNT.%s.AUTH.POLICY.UPDATE"
	userClaimsUpdateSubj      = "$SYS.REQ.USER.CLAIMS.UPDATE"
	userClaimsUpdatePlural    = "$SYS.REQ.USERS.CLAIMS.UPDATE"
	userClaimsUpdateSubjID    = "$SYS.REQ.USER.*.CLAIMS.UPDATE"
	userClaimsUpdatePluralID  = "$SYS.REQ.USERS.*.CLAIMS.UPDATE"
	acctUserClaimsUpdate      = "$SYS.REQ.ACCOUNT.*.USERS.CLAIMS.UPDATE"
	acctUserClaimUpdate       = "$SYS.REQ.ACCOUNT.*.USER.CLAIMS.UPDATE"
	acctUserClaimsUpdateID    = "$SYS.REQ.ACCOUNT.*.USER.*.CLAIMS.UPDATE"
	acctUserClaimsPluralID    = "$SYS.REQ.ACCOUNT.*.USERS.*.CLAIMS.UPDATE"
	acctOldUserClaimUpdate    = "$SYS.ACCOUNT.*.USER.CLAIMS.UPDATE"
	acctOldUserClaimsUpdateID = "$SYS.ACCOUNT.*.USER.*.CLAIMS.UPDATE"
)

type userPolicyState struct {
	claims   *jwt.UserClaims
	raw      string
	issuedAt int64
}

func stringSetDiff(oldValues, newValues []string) AuthzSubjectDiff {
	d := AuthzSubjectDiff{}
	old := make(map[string]struct{}, len(oldValues))
	for _, v := range oldValues {
		old[v] = struct{}{}
	}
	new := make(map[string]struct{}, len(newValues))
	for _, v := range newValues {
		new[v] = struct{}{}
		if _, ok := old[v]; !ok {
			d.Added = append(d.Added, v)
		}
	}
	for _, v := range oldValues {
		if _, ok := new[v]; !ok {
			d.Removed = append(d.Removed, v)
		}
	}
	return d
}

func splitQueuePermissionValues(values []string) (subjects, queues []string) {
	for _, v := range values {
		if strings.ContainsAny(v, " \t") {
			queues = append(queues, v)
		} else {
			subjects = append(subjects, v)
		}
	}
	return subjects, queues
}

func subscribeDiffs(oldPerms, newPerms *Permissions) (subAllow, subDeny, qAllow, qDeny AuthzSubjectDiff) {
	var oldAllow, oldDeny, newAllow, newDeny []string
	if oldPerms != nil && oldPerms.Subscribe != nil {
		oldAllow = oldPerms.Subscribe.Allow
		oldDeny = oldPerms.Subscribe.Deny
	}
	if newPerms != nil && newPerms.Subscribe != nil {
		newAllow = newPerms.Subscribe.Allow
		newDeny = newPerms.Subscribe.Deny
	}
	oldAllowSub, oldAllowQ := splitQueuePermissionValues(oldAllow)
	newAllowSub, newAllowQ := splitQueuePermissionValues(newAllow)
	oldDenySub, oldDenyQ := splitQueuePermissionValues(oldDeny)
	newDenySub, newDenyQ := splitQueuePermissionValues(newDeny)
	return stringSetDiff(oldAllowSub, newAllowSub),
		stringSetDiff(oldDenySub, newDenySub),
		stringSetDiff(oldAllowQ, newAllowQ),
		stringSetDiff(oldDenyQ, newDenyQ)
}

// DiffAuthzPolicies is the single permission difference calculation used by
// all authorization sources.
func DiffAuthzPolicies(oldPerms, newPerms *Permissions) *AuthzPolicyDiff {
	d := &AuthzPolicyDiff{}
	var oldPubAllow, oldPubDeny, newPubAllow, newPubDeny []string
	if oldPerms != nil && oldPerms.Publish != nil {
		oldPubAllow = oldPerms.Publish.Allow
		oldPubDeny = oldPerms.Publish.Deny
	}
	if newPerms != nil && newPerms.Publish != nil {
		newPubAllow = newPerms.Publish.Allow
		newPubDeny = newPerms.Publish.Deny
	}
	d.PublishAllow = stringSetDiff(oldPubAllow, newPubAllow)
	d.PublishDeny = stringSetDiff(oldPubDeny, newPubDeny)
	d.SubscribeAllow, d.SubscribeDeny, d.QueueAllow, d.QueueDeny = subscribeDiffs(oldPerms, newPerms)

	var oldResp, newResp *ResponsePermission
	if oldPerms != nil {
		oldResp = oldPerms.Response
	}
	if newPerms != nil {
		newResp = newPerms.Response
	}
	if !sameResponsePermissions(oldResp, newResp) {
		rd := &AuthzResponseDiff{Changed: true}
		if newResp != nil {
			rd.MaxMsgs = newResp.MaxMsgs
			rd.Expires = newResp.Expires
		}
		if (oldResp == nil) != (newResp == nil) ||
			(oldResp != nil && newResp != nil && oldResp.MaxMsgs != newResp.MaxMsgs) {
			rd.MaxMsgsChanged = true
		}
		if (oldResp == nil) != (newResp == nil) ||
			(oldResp != nil && newResp != nil && oldResp.Expires != newResp.Expires) {
			rd.ExpiresChanged = true
		}
		d.Response = rd
	}

	if len(d.PublishAllow.Added) > 0 || len(d.PublishAllow.Removed) > 0 {
		d.Categories = append(d.Categories, "publish_allow")
	}
	if len(d.PublishDeny.Added) > 0 || len(d.PublishDeny.Removed) > 0 {
		d.Categories = append(d.Categories, "publish_deny")
	}
	if len(d.SubscribeAllow.Added) > 0 || len(d.SubscribeAllow.Removed) > 0 {
		d.Categories = append(d.Categories, "subscribe_allow")
	}
	if len(d.SubscribeDeny.Added) > 0 || len(d.SubscribeDeny.Removed) > 0 {
		d.Categories = append(d.Categories, "subscribe_deny")
	}
	if len(d.QueueAllow.Added) > 0 || len(d.QueueAllow.Removed) > 0 {
		d.Categories = append(d.Categories, "queue_allow")
	}
	if len(d.QueueDeny.Added) > 0 || len(d.QueueDeny.Removed) > 0 {
		d.Categories = append(d.Categories, "queue_deny")
	}
	if d.Response != nil {
		d.Categories = append(d.Categories, "response_permissions")
	}
	if len(d.Categories) == 0 {
		return nil
	}
	return d
}

func (r AuthzTerminationReason) Error() string { return string(r) }

func authzFailure(reason AuthzTerminationReason, format string, args ...any) error {
	return fmt.Errorf("%w: %s", reason, fmt.Sprintf(format, args...))
}

func classifyUserClaimDecodeError(err error) (AuthzTerminationReason, error) {
	if err == nil {
		return AuthzTerminationNone, nil
	}
	msg := err.Error()
	if strings.Contains(msg, "signature") {
		return AuthzReasonInvalidSignature, authzFailure(AuthzReasonInvalidSignature, "%v", err)
	}
	return AuthzReasonMalformedClaim, authzFailure(AuthzReasonMalformedClaim, "%v", err)
}

func userClaimAccountID(juc *jwt.UserClaims) string {
	if juc == nil {
		return _EMPTY_
	}
	if juc.IssuerAccount != _EMPTY_ {
		return juc.IssuerAccount
	}
	if nkeys.IsValidPublicAccountKey(juc.Issuer) {
		return juc.Issuer
	}
	return _EMPTY_
}

func (s *Server) verifyUserClaimForPolicy(juc *jwt.UserClaims, acc *Account) (AuthzTerminationReason, error) {
	if s == nil || juc == nil || acc == nil {
		return AuthzReasonEvaluationUnavailable, errors.New("authorization evaluation context is unavailable")
	}
	acc.mu.RLock()
	accountIssuer := acc.Issuer
	_, issuerKnown := acc.hasIssuerNoLock(juc.Issuer)
	acc.mu.RUnlock()
	if !s.isTrustedIssuer(accountIssuer) {
		return AuthzReasonUntrustedIssuer, authzFailure(AuthzReasonUntrustedIssuer, "account issuer is not trusted")
	}
	if !issuerKnown {
		return AuthzReasonUntrustedIssuer, authzFailure(AuthzReasonUntrustedIssuer, "user JWT issuer is not in account signing key set")
	}
	if scope, ok := acc.hasIssuer(juc.Issuer); ok && scope != nil {
		if err := scope.ValidateScopedSigner(juc); err != nil {
			return AuthzReasonUntrustedIssuer, authzFailure(AuthzReasonUntrustedIssuer, "%v", err)
		}
		if userScope, ok := scope.(*jwt.UserScope); ok {
			processed, err := processUserPermissionsTemplate(userScope.Template, juc, acc)
			if err != nil {
				return AuthzReasonMalformedClaim, authzFailure(AuthzReasonMalformedClaim, "%v", err)
			}
			juc.UserPermissionLimits = processed
		}
	}
	vr := jwt.CreateValidationResults()
	juc.Validate(vr)
	if vr.IsBlocking(true) {
		// Expiry is classified separately so callers can terminate with a stable reason.
		now := time.Now().Unix()
		if juc.Expires != 0 && juc.Expires <= now {
			return AuthzReasonClaimExpired, authzFailure(AuthzReasonClaimExpired, "user claim has expired")
		}
		return AuthzReasonMalformedClaim, authzFailure(AuthzReasonMalformedClaim, "%v", vr)
	}
	if acc.IsExpired() {
		return AuthzReasonClaimExpired, authzFailure(AuthzReasonClaimExpired, "account claim has expired")
	}
	if acc.checkUserRevoked(juc.Subject, juc.IssuedAt) {
		return AuthzReasonRevoked, authzFailure(AuthzReasonRevoked, "user claim is revoked")
	}
	return AuthzTerminationNone, nil
}

func (a *Account) currentUserPolicy(user string) *userPolicyState {
	if a == nil || user == _EMPTY_ {
		return nil
	}
	a.mu.RLock()
	st := a.userPolicies[user]
	a.mu.RUnlock()
	return st
}

// reconcileConnectUserPolicy applies a newer centrally submitted user policy to
// a (possibly old) claim presented at reconnect. It preserves connection-time
// validation semantics while ensuring an old claim cannot restore old rights.
func (s *Server) reconcileConnectUserPolicy(acc *Account, juc *jwt.UserClaims) *jwt.UserClaims {
	st := acc.currentUserPolicy(juc.Subject)
	if st == nil || st.claims == nil || st.issuedAt < juc.IssuedAt {
		return juc
	}
	// Equal timestamps are treated as "server already has the authoritative
	// copy"; only an actually newer iat can replace it.
	if st.issuedAt == juc.IssuedAt && st.raw == _EMPTY_ {
		return juc
	}
	return st.claims
}

func (s *Server) terminateUserPolicyClients(acc *Account, juc *jwt.UserClaims, reason AuthzTerminationReason) int {
	if acc == nil || juc == nil {
		return 0
	}
	acc.mu.Lock()
	var clients []*client
	for c := range acc.clients {
		if c != nil && c.kind == CLIENT {
			clients = append(clients, c)
		}
	}
	acc.mu.Unlock()
	n := 0
	for _, c := range clients {
		c.mu.Lock()
		match := c.pubKey == juc.Subject || (c.user != nil && c.user.Nkey == juc.Subject)
		c.mu.Unlock()
		if !match {
			continue
		}
		n++
		switch reason {
		case AuthzReasonRevoked:
			c.sendErrAndDebug("User Authentication Revoked")
			c.closeConnection(Revocation)
		case AuthzReasonClaimExpired:
			c.authExpired()
		case AuthzReasonUntrustedIssuer:
			c.closeConnection(AuthenticationViolation)
		default:
			c.closeConnection(ClientClosed)
		}
	}
	return n
}

func (c *client) applyUserAuthPolicy(nu *NkeyUser) (*AuthzPolicyDiff, int) {
	if c == nil || nu == nil {
		return nil, 0
	}
	c.mu.Lock()
	if c.isClosed() {
		c.mu.Unlock()
		return nil, 0
	}
	var oldPerms *Permissions
	if c.user != nil {
		oldPerms = c.user.Permissions
	}
	diff := DiffAuthzPolicies(oldPerms, nu.Permissions)
	var responseUnchanged bool
	if c.user != nil && c.user.Permissions != nil && nu.Permissions != nil {
		responseUnchanged = sameResponsePermissions(c.user.Permissions.Response, nu.Permissions.Response)
	}
	replies := c.replies
	subsBefore := len(c.subs)

	c.user = nu.clone()
	if nu.Permissions == nil {
		c.perms = nil
		c.mperms = nil
		c.darray = nil
		c.replies = nil
	} else {
		c.setPermissions(nu.Permissions)
		if responseUnchanged {
			c.replies = replies
		} else if nu.Permissions.Response == nil {
			c.replies = nil
		}
	}
	if c.acc != nil && c.acc.hasExternalAuth() {
		c.denyAuthCalloutSubjects(!c.flags.isSet(authCallout) && c.acc.isExternalAuthUser(c.user.Nkey))
	}
	if nu.Issued > 0 {
		c.pubKey = nu.Nkey
	}
	c.mu.Unlock()

	c.processSubsOnConfigReload(nil)

	if diff != nil {
		c.mu.Lock()
		if removed := subsBefore - len(c.subs); removed > 0 {
			diff.RemovedSubscriptions = removed
		}
		c.mu.Unlock()
	}
	return diff, 1
}

func (s *Server) auditAuthzEvaluation(ev *AuthzAuditEvent, acc *Account) {
	if s == nil || ev == nil {
		return
	}
	ev.Effective = ev.Applied || ev.Terminated
	ev.Affected = ev.AffectedConnections
	ev.AffectedClients = ev.AffectedConnections
	ev.ConnectionCount = ev.AffectedConnections
	ev.ClientCount = ev.AffectedConnections
	ev.Count = ev.AffectedConnections
	ev.AffectedCount = ev.AffectedConnections
	ev.NumAffected = ev.AffectedConnections
	if ev.TerminatedConnections > ev.AffectedConnections {
		ev.Affected = ev.TerminatedConnections
	}
	ev.Trigger = ev.Source
	if ev.Reason != AuthzTerminationNone {
		ev.TerminationReason = ev.Reason
	}
	if ev.Diff != nil {
		ev.DiffCategories = ev.Diff.Categories
		ev.Categories = ev.Diff.Categories
	}
	sid := s.ID()
	ev.ServerID = sid
	if ev.TypedEvent.Type == _EMPTY_ {
		ev.TypedEvent = TypedEvent{Type: authzAuditEventType, ID: s.nextEventID(), Time: time.Now().UTC()}
	}
	if ev.Error != _EMPTY_ {
		if ev.Applied {
			s.Noticef("Authz policy applied source=%s account=%q user=%q affected=%d categories=%v",
				ev.Source, ev.Account, ev.User, ev.AffectedConnections, ev.Categories)
		} else {
			s.Warnf("Authz policy not applied source=%s account=%q user=%q reason=%s affected=%d err=%q",
				ev.Source, ev.Account, ev.User, ev.Reason, ev.AffectedConnections, ev.Error)
		}
	} else {
		s.Noticef("Authz policy evaluation source=%s account=%q user=%q affected=%d effective=%t categories=%v reason=%s",
			ev.Source, ev.Account, ev.User, ev.AffectedConnections, ev.Effective, ev.Categories, ev.Reason)
	}
	if !s.EventsEnabled() {
		return
	}
	// Audit events are operator/system events. The account ID remains part of
	// the subject and payload, but the event is delivered through $SYS.
	subject := fmt.Sprintf(authzAuditEventSubj, ev.Account)
	if ev.Account == _EMPTY_ {
		subject = fmt.Sprintf("$SYS.SERVER.%s.AUTH.POLICY.UPDATE", sid)
	}
	s.sendInternalMsgLocked(subject, _EMPTY_, nil, ev)
}

// UpdateUserClaims applies a decoded user claim through the same evaluation,
// diff, version, audit, and incremental application path as a JWT update.
func (s *Server) UpdateUserClaims(a *Account, juc *jwt.UserClaims) error {
	_, err := s.updateUserClaims(a, juc)
	return err
}

func (s *Server) updateUserClaims(a *Account, juc *jwt.UserClaims) (*AuthzAuditEvent, error) {
	ev := &AuthzAuditEvent{Source: AuthzSourceUserUpdate}
	if a == nil || juc == nil {
		ev.Reason = AuthzReasonEvaluationUnavailable
		ev.Error = "account and user claims are required"
		s.auditAuthzEvaluation(ev, a)
		return ev, errors.New(ev.Error)
	}
	ev.Account = a.Name
	ev.User = juc.Subject
	if reason, err := s.verifyUserClaimForPolicy(juc, a); err != nil {
		ev.Reason = reason
		ev.Error = err.Error()
		if reason == AuthzReasonRevoked || reason == AuthzReasonClaimExpired {
			n := s.terminateUserPolicyClients(a, juc, reason)
			ev.AffectedConnections = n
			ev.TerminatedConnections = n
			ev.Terminated = n > 0
		}
		s.auditAuthzEvaluation(ev, a)
		return ev, err
	}
	return s.storeAndApplyUserClaim(a, juc, _EMPTY_, ev)
}

func (s *Server) storeAndApplyUserClaim(acc *Account, juc *jwt.UserClaims, raw string, ev *AuthzAuditEvent) (*AuthzAuditEvent, error) {
	if ev == nil {
		ev = &AuthzAuditEvent{Source: AuthzSourceUserUpdate}
	}
	ev.Account = acc.Name
	ev.User = juc.Subject
	acc.mu.Lock()
	if acc.userPolicies == nil {
		acc.userPolicies = make(map[string]*userPolicyState)
	}
	if old := acc.userPolicies[juc.Subject]; old != nil && juc.IssuedAt < old.issuedAt {
		acc.mu.Unlock()
		err := authzFailure(AuthzReasonVersionExpired, "user claim iat %d is older than %d", juc.IssuedAt, old.issuedAt)
		ev.Reason = AuthzReasonVersionExpired
		ev.Error = err.Error()
		s.auditAuthzEvaluation(ev, acc)
		return ev, err
	}
	acc.userPolicies[juc.Subject] = &userPolicyState{claims: juc, raw: raw, issuedAt: juc.IssuedAt}
	var clients []*client
	for c := range acc.clients {
		if c != nil && c.kind == CLIENT {
			clients = append(clients, c)
		}
	}
	acc.mu.Unlock()

	nu := buildInternalNkeyUser(juc, nil, acc)
	affected := 0
	var diff *AuthzPolicyDiff
	for _, c := range clients {
		c.mu.Lock()
		userMatch := c.pubKey == juc.Subject || (c.user != nil && c.user.Nkey == juc.Subject)
		c.mu.Unlock()
		if !userMatch {
			continue
		}
		d, n := c.applyUserAuthPolicy(nu)
		if n > 0 {
			affected += n
			if diff == nil {
				diff = d
			}
		}
	}
	ev.AffectedConnections = affected
	ev.Diff = diff
	ev.Applied = true
	s.auditAuthzEvaluation(ev, acc)
	return ev, nil
}

// ApplyUserClaimJWT validates, versions, stores, and incrementally applies a
// user claim update to only local connections authenticated as that user.
func (s *Server) ApplyUserClaimJWT(raw string) (*AuthzAuditEvent, error) {
	return s.applyUserClaimJWT(raw, _EMPTY_)
}

// ApplyUserClaimJWTForAccount applies an account-scoped request whose subject
// identifies the owning account even if the claim omits IssuerAccount.
func (s *Server) ApplyUserClaimJWTForAccount(raw, accountID string) (*AuthzAuditEvent, error) {
	return s.applyUserClaimJWT(raw, accountID)
}

// UpdateUserClaimJWT is the programmatic request/response entrypoint alias.
func (s *Server) UpdateUserClaimJWT(raw string) error {
	_, err := s.applyUserClaimJWT(raw, _EMPTY_)
	return err
}

// UpdateUserJWT is a compatibility alias for callers using the shorter name.
func (s *Server) UpdateUserJWT(raw string) error {
	return s.UpdateUserClaimJWT(raw)
}

func (s *Server) applyUserClaimJWT(raw, expectedAccount string) (*AuthzAuditEvent, error) {
	ev := &AuthzAuditEvent{Source: AuthzSourceUserUpdate}
	if strings.TrimSpace(raw) == _EMPTY_ {
		ev.Reason = AuthzReasonMalformedClaim
		ev.Error = "request body is empty"
		s.auditAuthzEvaluation(ev, nil)
		return ev, errors.New(ev.Error)
	}
	juc, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		ev.Reason, err = classifyUserClaimDecodeError(err)
		ev.Error = err.Error()
		s.auditAuthzEvaluation(ev, nil)
		return ev, err
	}
	ev.User = juc.Subject
	accountID := juc.IssuerAccount
	if accountID == _EMPTY_ && nkeys.IsValidPublicAccountKey(juc.Issuer) && expectedAccount == _EMPTY_ {
		accountID = juc.Issuer
	}
	if accountID == _EMPTY_ {
		accountID = expectedAccount
	}
	if expectedAccount != _EMPTY_ && accountID != _EMPTY_ && expectedAccount != accountID {
		ev.Reason = AuthzReasonSubjectMismatch
		err = authzFailure(AuthzReasonSubjectMismatch, "subject account %q does not match JWT account %q", expectedAccount, accountID)
		ev.Error = err.Error()
		s.auditAuthzEvaluation(ev, nil)
		return ev, err
	}
	ev.Account = accountID
	if accountID == _EMPTY_ {
		ev.Reason = AuthzReasonSubjectMismatch
		err = authzFailure(AuthzReasonSubjectMismatch, "cannot determine account for user claim")
		ev.Error = err.Error()
		s.auditAuthzEvaluation(ev, nil)
		return ev, err
	}
	acc, err := s.LookupAccount(accountID)
	if err != nil || acc == nil {
		ev.Reason = AuthzReasonAccountUnavailable
		if err == nil {
			err = authzFailure(AuthzReasonAccountUnavailable, "account %q is not available", accountID)
		} else {
			err = authzFailure(AuthzReasonAccountUnavailable, "%v", err)
		}
		ev.Error = err.Error()
		s.auditAuthzEvaluation(ev, nil)
		return ev, err
	}
	ev.Account = acc.Name

	reason, err := s.verifyUserClaimForPolicy(juc, acc)
	if err != nil {
		ev.Reason = reason
		ev.Error = err.Error()
		if reason == AuthzReasonRevoked || reason == AuthzReasonClaimExpired {
			n := s.terminateUserPolicyClients(acc, juc, reason)
			ev.AffectedConnections = n
			ev.TerminatedConnections = n
			ev.Terminated = n > 0
		}
		s.auditAuthzEvaluation(ev, acc)
		return ev, err
	}

	return s.storeAndApplyUserClaim(acc, juc, raw, ev)
}

func userUpdateSubjectIdentity(subject string) (accountID, userID string, ok bool) {
	toks := strings.Split(subject, tsep)
	// $SYS.REQ.CLAIMS.UPDATE is the shared global claims entrypoint.
	if len(toks) == 4 && toks[0] == "$SYS" && toks[1] == "REQ" &&
		toks[2] == "CLAIMS" && toks[3] == "UPDATE" {
		return _EMPTY_, _EMPTY_, true
	}
	// $SYS.REQ.USER(S).CLAIMS.UPDATE
	if len(toks) == 5 && toks[0] == "$SYS" && toks[1] == "REQ" &&
		(toks[2] == "USER" || toks[2] == "USERS") &&
		toks[3] == "CLAIMS" && toks[4] == "UPDATE" {
		return _EMPTY_, _EMPTY_, true
	}
	// $SYS.REQ.USER(S).<user>.CLAIMS.UPDATE
	if len(toks) == 6 && toks[0] == "$SYS" && toks[1] == "REQ" &&
		(toks[2] == "USER" || toks[2] == "USERS") &&
		toks[4] == "CLAIMS" && toks[5] == "UPDATE" {
		return _EMPTY_, toks[3], true
	}
	// $SYS.REQ.ACCOUNT.<account>.USER(S).CLAIMS.UPDATE
	if len(toks) == 7 && toks[0] == "$SYS" && toks[1] == "REQ" && toks[2] == "ACCOUNT" &&
		(toks[4] == "USERS" || toks[4] == "USER") &&
		toks[5] == "CLAIMS" && toks[6] == "UPDATE" {
		return toks[3], _EMPTY_, true
	}
	// $SYS.ACCOUNT.<account>.USER.CLAIMS.UPDATE
	if len(toks) == 6 && toks[0] == "$SYS" && toks[1] == "ACCOUNT" &&
		toks[3] == "USER" && toks[4] == "CLAIMS" && toks[5] == "UPDATE" {
		return toks[2], _EMPTY_, true
	}
	// $SYS.REQ.ACCOUNT.<account>.USER.<user>.CLAIMS.UPDATE
	if len(toks) == 8 && toks[0] == "$SYS" && toks[1] == "REQ" && toks[2] == "ACCOUNT" &&
		(toks[4] == "USER" || toks[4] == "USERS") && toks[6] == "CLAIMS" && toks[7] == "UPDATE" {
		return toks[3], toks[5], true
	}
	// $SYS.ACCOUNT.<account>.USER.<user>.CLAIMS.UPDATE
	if len(toks) == 7 && toks[0] == "$SYS" && toks[1] == "ACCOUNT" &&
		toks[3] == "USER" && toks[5] == "CLAIMS" && toks[6] == "UPDATE" {
		return toks[2], toks[4], true
	}
	return _EMPTY_, _EMPTY_, false
}

func parseUserClaimUpdatePayload(msg []byte) ([]string, bool, error) {
	trimmed := strings.TrimSpace(string(msg))
	if trimmed == _EMPTY_ {
		return nil, false, errors.New("request body is empty")
	}
	if trimmed[0] != '[' && trimmed[0] != '{' {
		return []string{trimmed}, false, nil
	}
	if trimmed[0] == '[' {
		var rawItems []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &rawItems); err != nil {
			return nil, true, err
		}
		out := make([]string, 0, len(rawItems))
		for _, item := range rawItems {
			var s string
			if err := json.Unmarshal(item, &s); err == nil {
				out = append(out, s)
				continue
			}
			var obj struct {
				JWT      string   `json:"jwt"`
				UserJWT  string   `json:"user_jwt"`
				ClaimJWT string   `json:"claim_jwt"`
				Claims   []string `json:"claims"`
				JWTs     []string `json:"jwts"`
			}
			if err := json.Unmarshal(item, &obj); err != nil {
				return nil, true, err
			}
			switch {
			case obj.JWT != _EMPTY_:
				out = append(out, obj.JWT)
			case obj.UserJWT != _EMPTY_:
				out = append(out, obj.UserJWT)
			case obj.ClaimJWT != _EMPTY_:
				out = append(out, obj.ClaimJWT)
			default:
				out = append(out, append(append([]string{}, obj.Claims...), obj.JWTs...)...)
			}
		}
		return out, true, nil
	}
	var obj struct {
		JWT      string   `json:"jwt"`
		UserJWT  string   `json:"user_jwt"`
		ClaimJWT string   `json:"claim_jwt"`
		JWTs     []string `json:"jwts"`
		Claims   []string `json:"claims"`
		Users    []string `json:"users"`
	}
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, false, err
	}
	if obj.JWT != _EMPTY_ {
		return []string{obj.JWT}, false, nil
	}
	if obj.UserJWT != _EMPTY_ {
		return []string{obj.UserJWT}, false, nil
	}
	if obj.ClaimJWT != _EMPTY_ {
		return []string{obj.ClaimJWT}, false, nil
	}
	out := append(append(append([]string{}, obj.JWTs...), obj.Claims...), obj.Users...)
	return out, true, nil
}

func checkUserClaimSubjects(raw, subjectAccount, subjectUser string) (*jwt.UserClaims, error) {
	juc, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return nil, err
	}
	if subjectUser != _EMPTY_ && juc.Subject != subjectUser {
		return juc, authzFailure(AuthzReasonSubjectMismatch, "subject user %q does not match JWT subject %q", subjectUser, juc.Subject)
	}
	if subjectAccount != _EMPTY_ && juc.IssuerAccount != _EMPTY_ && subjectAccount != juc.IssuerAccount {
		return juc, authzFailure(AuthzReasonSubjectMismatch, "subject account %q does not match JWT account %q", subjectAccount, juc.IssuerAccount)
	}
	return juc, nil
}

func (c *client) rejectUnauthorizedUserClaimUpdate() bool {
	if c == nil || c.kind != CLIENT || c.srv == nil {
		return false
	}
	subject := string(c.pa.subject)
	// Keep this off the normal publish hot path: only tokenize the small set of
	// system claim-update subjects.
	if !strings.HasPrefix(subject, "$SYS.") || !strings.HasSuffix(subject, "CLAIMS.UPDATE") {
		return false
	}
	if _, _, ok := userUpdateSubjectIdentity(subject); !ok {
		return false
	}
	c.mu.RLock()
	acc := c.acc
	submitter := c.pubKey
	reply := string(c.pa.reply)
	c.mu.RUnlock()
	if acc == nil {
		return false
	}
	if sysAcc := c.srv.SystemAccount(); sysAcc != nil && acc.Name == sysAcc.Name {
		return false
	}
	ev := &AuthzAuditEvent{
		Source: AuthzSourceUserUpdate, Account: acc.Name, User: submitter,
		Reason: AuthzReasonUnauthorizedSubmitter,
		Error:  "user claim updates require an authenticated system account principal",
	}
	c.srv.auditAuthzEvaluation(ev, acc)
	if reply != _EMPTY_ {
		resp := ServerAPIClaimUpdateResponse{
			Error: &ClaimUpdateError{
				Account:     submitter,
				Code:        403,
				Description: ev.Error,
			},
		}
		_ = c.srv.sendInternalAccountMsg(acc, reply, &resp)
	}
	c.pubPermissionViolation(c.pa.subject)
	return true
}

func (s *Server) userClaimUpdate(_ *subscription, c *client, _ *Account, subject, resp string, _ []byte, msg []byte) {
	if !s.EventsEnabled() {
		return
	}
	subjectAccount, subjectUser, ok := userUpdateSubjectIdentity(subject)
	if !ok {
		s.Debugf("Received user claims update on bad subject %q", subject)
		return
	}
	// noInlineCallback has already split headers and payload for this handler.
	// The shared claims subject also carries account claims. Let the established
	// account path own those and only intercept user claims here.
	if len(msg) > 0 {
		if _, err := jwt.DecodeAccountClaims(string(msg)); err == nil {
			return
		}
	}
	if c != nil && c.kind == CLIENT {
		s.mu.RLock()
		sysAcc := s.sys.account
		s.mu.RUnlock()
		if sysAcc == nil || c.acc == nil || c.acc.Name != sysAcc.Name {
			ev := &AuthzAuditEvent{
				Source: AuthzSourceUserUpdate, Account: subjectAccount, User: subjectUser,
				Reason: AuthzReasonUnauthorizedSubmitter,
				Error:  "user claim updates require an authenticated system account principal",
			}
			s.auditAuthzEvaluation(ev, nil)
			if resp != _EMPTY_ {
				respondToUpdate(s, resp, subjectUser, "user jwt update resulted in error", errors.New(ev.Error))
			}
			return
		}
	}
	rawClaims, batch, parseErr := parseUserClaimUpdatePayload(msg)
	if parseErr != nil {
		ev := &AuthzAuditEvent{
			Source: AuthzSourceUserUpdate, Account: subjectAccount, User: subjectUser,
			Reason: AuthzReasonMalformedClaim, Error: parseErr.Error(),
		}
		s.auditAuthzEvaluation(ev, nil)
		if resp != _EMPTY_ {
			respondToUpdate(s, resp, subjectUser, "user jwt update resulted in error", parseErr)
		}
		return
	}

	var submitter string
	if c != nil && c.kind == CLIENT {
		c.mu.Lock()
		submitter = c.pubKey
		c.mu.Unlock()
	}
	results := make([]*AuthzAuditEvent, 0, len(rawClaims))
	for _, raw := range rawClaims {
		juc, subjectErr := checkUserClaimSubjects(raw, subjectAccount, subjectUser)
		if subjectErr == nil && submitter != _EMPTY_ && juc != nil && juc.Subject == submitter {
			subjectErr = authzFailure(AuthzReasonUnauthorizedSubmitter, "users cannot submit claim updates for themselves")
		}
		if subjectErr != nil {
			reason := AuthzReasonSubjectMismatch
			var authErr AuthzTerminationReason
			if errors.As(subjectErr, &authErr) {
				reason = authErr
			}
			ev := &AuthzAuditEvent{
				Source: AuthzSourceUserUpdate, Account: subjectAccount, User: subjectUser,
				Reason: reason, Error: subjectErr.Error(),
			}
			if juc != nil {
				ev.User = juc.Subject
				ev.Account = userClaimAccountID(juc)
			}
			s.auditAuthzEvaluation(ev, nil)
			results = append(results, ev)
			continue
		}
		ev, _ := s.ApplyUserClaimJWTForAccount(raw, subjectAccount)
		if ev == nil {
			ev = &AuthzAuditEvent{Source: AuthzSourceUserUpdate, Reason: AuthzReasonEvaluationUnavailable, Error: "evaluation returned no result"}
		}
		results = append(results, ev)
	}

	if batch {
		if resp != _EMPTY_ {
			s.sendInternalMsgLocked(resp, _EMPTY_, nil, &AuthzUserClaimBatchResponse{Results: results})
		}
		return
	}
	ev := results[0]
	key := subjectUser
	if ev.User != _EMPTY_ {
		key = ev.User
	}
	if !ev.Effective && ev.Error != _EMPTY_ {
		respondToUpdate(s, resp, key, "user jwt update resulted in error", errors.New(ev.Error))
		return
	}
	respondToUpdate(s, resp, key, "user jwt updated", nil)
}
