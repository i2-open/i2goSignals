package main

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestReviewSubjectFilterCmdParses verifies the kong parser recognizes
// `review subject-filter <alias> [--subject ...]` (PRD #97 issue #101). The
// command is thin glue over the tested admin endpoint, so the parser-level
// pin is enough — the wire behavior is covered by the server handler tests.
func TestReviewSubjectFilterCmdParses(t *testing.T) {
    pd, err := initParser(&CLI{})
    require.NoError(t, err)

    ctx, err := pd.parser.Parse([]string{"review", "subject-filter", "my-stream"})
    require.NoError(t, err, "review subject-filter <alias> must parse")
    assert.Equal(t, "review subject-filter <alias>", ctx.Command())

    rcmd := &pd.cli.Review.SubjectFilter
    assert.Equal(t, "my-stream", rcmd.Alias)
    assert.Empty(t, rcmd.Subject, "default omits --subject")

    ctx, err = pd.parser.Parse([]string{
        "review", "subject-filter", "my-stream",
        "--subject", `{"format":"email","email":"alice@example.com"}`,
    })
    require.NoError(t, err, "review subject-filter --subject must parse")
    assert.Equal(t, `{"format":"email","email":"alice@example.com"}`, pd.cli.Review.SubjectFilter.Subject)
    _ = ctx
}
