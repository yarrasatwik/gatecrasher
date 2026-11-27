package mapper

import (
	"slices"
	"strings"
)

// Forgeability answers, for one segment condition, whether a client holding
// only the public key can make the condition true. The result is "yes", "no"
// or "unknown"; unknown must never be reported as safe (spec §8.7).
//
//   - a trait is forgeable when the environment lets clients set traits and the
//     trait is not on the server-only list; IS_NOT_SET is satisfied by simply
//     omitting the trait, so it is forgeable unless a server may always set it;
//   - identity properties and identifier-hashed PERCENTAGE_SPLIT conditions are
//     forgeable exactly when the client chooses its own identifier;
//   - $.environment.* is not client controlled; any other JSONPath is unknown.
func Forgeability(cond Condition, envAllowsClientTraits bool, serverOnlyTraits []string, clientSetsIdentifier bool) string {
	kind, name := propertyKind(cond.Property)
	switch kind {
	case kindIdentifier, kindIdentityKey:
		return yesNo(clientSetsIdentifier)
	case kindNone:
		if cond.Operator == OpPercentSplit {
			return yesNo(clientSetsIdentifier)
		}
		return "unknown"
	case kindEnvironment:
		return "no"
	case kindOther:
		return "unknown"
	}
	serverOnly := slices.Contains(serverOnlyTraits, name)
	if cond.Operator == OpIsNotSet {
		if serverOnly {
			return "unknown"
		}
		return "yes"
	}
	return yesNo(envAllowsClientTraits && !serverOnly)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// combineForgeability folds per-input results: any "no" blocks the whole
// input, otherwise any "unknown" keeps it unknown, otherwise "yes".
func combineForgeability(parts []string) string {
	out := "yes"
	for _, p := range parts {
		switch p {
		case "no":
			return "no"
		case "unknown":
			out = "unknown"
		}
	}
	return out
}

type propKind int

const (
	kindTrait propKind = iota
	kindIdentifier
	kindIdentityKey
	kindEnvironment
	kindOther
	kindNone
)

const (
	identifierProp  = "$.identity.identifier"
	identityKeyProp = "$.identity.key"
	traitPathPrefix = "$.identity.traits."
)

// propertyKind classifies a condition property and returns the trait name for
// trait properties (including $.identity.traits.<name> paths).
func propertyKind(p string) (propKind, string) {
	switch {
	case p == "":
		return kindNone, ""
	case p == identifierProp:
		return kindIdentifier, ""
	case p == identityKeyProp:
		return kindIdentityKey, ""
	case strings.HasPrefix(p, traitPathPrefix) && len(p) > len(traitPathPrefix):
		return kindTrait, p[len(traitPathPrefix):]
	case strings.HasPrefix(p, "$.environment"):
		return kindEnvironment, ""
	case strings.HasPrefix(p, "$."):
		return kindOther, ""
	}
	return kindTrait, p
}
