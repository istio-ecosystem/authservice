# Contributing

We welcome contributions from the community. Please read the following guidelines carefully to
maximize the chances of your PR being merged.

## Coding Style

* To ensure your change passes format checks, run `make check`. To format your files, you can run `make format`.
* We follow standard Go table-driven tests and use the `testify` library to assert correctness. 
  To verify all tests pass, you can run `make test`.

## Code Reviews

* The pull request title should describe what the change does and not embed issue numbers.
  The pull request should only be blank when the change is minor. Any feature should include
  a description of the change and what motivated it. If the change or design changes through
  review, please keep the title and description updated accordingly.
* A single approval is sufficient to merge. If a reviewer asks for
  changes in a PR they should be addressed before the PR is merged,
  even if another reviewer has already approved the PR.
* During the review, address the comments and commit the changes
  _without_ squashing the commits. This facilitates incremental reviews
  since the reviewer does not go through all the code again to find out
  what has changed since the last review. When a change goes out of sync with main,
  please rebase and force push, keeping the original commits where practical.
* Commits are squashed prior to merging a pull request, using the title
  as commit message by default. Maintainers may request contributors to
  edit the pull request tite to ensure that it remains descriptive as a
  commit message. Alternatively, maintainers may change the commit message directly.
