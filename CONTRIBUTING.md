# Contribution Guidelines

netlink accepts contributions via GitHub pull request(PR). This document outlines some of the conventions on how to contribute
code to the project.

## General

* One commit per PR.
* A PR covers a single area/functionality (e.g  extension of devlink command and link command should go in separate PRs).
* Each PR should be covered by unit tests when applicable.
* The goal of Netlink package is to follow iproute2 behavior. When in doubt refer to iproute2 [source code](https://github.com/iproute2/iproute2).

## Code Style

Please follows the standard formatting recommendations and language idioms set out in [Effective Go](https://golang.org/doc/effective_go.html)
and in the [Go Code Review Comments wiki](https://github.com/golang/go/wiki/CodeReviewComments).

## Commit Message Style

Each commit is expected to comply with the following format:

```
Change summary

More detailed explanation of your changes: Why and how.
Wrap it to 72 characters.
See [here] (https://chris.beams.io/posts/git-commit/)
for some more good advices.
```

For example:

```
Fix poorly named identifiers

One identifier, fnname, in func.go was poorly named. It has been renamed
to fnName. Another identifier retval was not needed and has been removed
entirely.
``` 

> __Note:__ [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#summary) style is not enforced however is allowed
