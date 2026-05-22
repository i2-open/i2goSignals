package main

import (
    "encoding/json"
    "fmt"
    "strings"

    "github.com/i2-open/i2goSignals/pkg/goSet"
)

// subjectArgFlags carries the format field-flag values that the subject-
// argument parser turns into a goSet.SubjectIdentifier. Each non-empty member
// fixes the subject format (PRD #106): the format is inferred from which flag
// is set — there is deliberately no --format flag.
//
// account and uri both populate the SubjectIdentifier.Uri member, so they are
// distinct flags that each pin their own format.
type subjectArgFlags struct {
    Email       string
    PhoneNumber string
    Iss         string
    Sub         string
    Id          string
    Url         string
    Username    string
    ExternalId  string
    Account     string
    Uri         string
}

// parseSubjectArg is the shared, pure subject-input surface for the
// subject-filter CLI (PRD #106). It takes a positional JSON argument and the
// set of format field-flag values and returns a goSet.SubjectIdentifier.
//
// Positional JSON and field flags are mutually exclusive: complex subjects,
// the aliases array, the scim format, and any unrecognised format are supplied
// as positional JSON; the field flags are the ergonomic path for the seven
// simple formats. The format is inferred from which field flag is set.
//
// It has no HTTP and no Kong dependency so it is testable in isolation and is
// reused later by `set subject-filter add`/`remove`.
func parseSubjectArg(jsonArg string, flags subjectArgFlags) (*goSet.SubjectIdentifier, error) {
    set := flags.setFlags()
    if jsonArg != "" {
        if len(set) > 0 {
            return nil, fmt.Errorf(
                "a positional subject JSON argument and the format field flags (%s) are mutually exclusive",
                strings.Join(set, ", "))
        }
        var sub goSet.SubjectIdentifier
        if err := json.Unmarshal([]byte(jsonArg), &sub); err != nil {
            return nil, fmt.Errorf("subject argument must be a SubjectIdentifier JSON literal: %w", err)
        }
        return &sub, nil
    }
    if len(set) == 0 {
        // No subject supplied at all — callers treat a nil subject as "no
        // point lookup requested".
        return nil, nil
    }
    return subjectFromFlags(flags)
}

// setFlags returns the names of the format field flags that carry a value, in
// a stable order, so error messages can name exactly what the operator gave.
// --iss and --sub are reported as the single iss_sub format pair.
func (f subjectArgFlags) setFlags() []string {
    var set []string
    if f.Email != "" {
        set = append(set, "--email")
    }
    if f.PhoneNumber != "" {
        set = append(set, "--phone-number")
    }
    if f.Iss != "" || f.Sub != "" {
        set = append(set, "--iss/--sub")
    }
    if f.Id != "" {
        set = append(set, "--id")
    }
    if f.Url != "" {
        set = append(set, "--url")
    }
    if f.Username != "" {
        set = append(set, "--username")
    }
    if f.ExternalId != "" {
        set = append(set, "--external-id")
    }
    if f.Account != "" {
        set = append(set, "--account")
    }
    if f.Uri != "" {
        set = append(set, "--uri")
    }
    return set
}

// subjectFromFlags derives a goSet.SubjectIdentifier from the format field
// flags, inferring the format from which flag is set. account, uri (and scim)
// all populate the Uri member, so --account and --uri are distinct flags that
// each pin their own format. It assumes at least one flag is set.
func subjectFromFlags(flags subjectArgFlags) (*goSet.SubjectIdentifier, error) {
    if set := flags.setFlags(); len(set) > 1 {
        return nil, fmt.Errorf(
            "the format field flags (%s) belong to more than one format; a subject has exactly one format",
            strings.Join(set, ", "))
    }
    sub := &goSet.SubjectIdentifier{}
    switch {
    case flags.Email != "":
        sub.Format = "email"
        sub.Email = flags.Email
    case flags.PhoneNumber != "":
        sub.Format = "phone_number"
        sub.PhoneNumber = flags.PhoneNumber
    case flags.Iss != "" || flags.Sub != "":
        if flags.Iss == "" {
            return nil, fmt.Errorf("the iss_sub format requires --iss alongside --sub")
        }
        if flags.Sub == "" {
            return nil, fmt.Errorf("the iss_sub format requires --sub alongside --iss")
        }
        sub.Format = "iss_sub"
        sub.Issuer = flags.Iss
        sub.Sub = flags.Sub
    case flags.Id != "":
        sub.Format = "opaque"
        sub.Id = flags.Id
    case flags.Url != "":
        sub.Format = "did"
        sub.Url = flags.Url
    case flags.Username != "":
        sub.Format = "username"
        sub.Username = flags.Username
    case flags.ExternalId != "":
        sub.Format = "externalId"
        sub.ExternalId = flags.ExternalId
    case flags.Account != "":
        sub.Format = "account"
        sub.Uri = flags.Account
    case flags.Uri != "":
        sub.Format = "uri"
        sub.Uri = flags.Uri
    }
    return sub, nil
}
