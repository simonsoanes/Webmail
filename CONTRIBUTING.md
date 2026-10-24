# Contributing

Thanks for your interest in Nullify.WebMail. Issues and pull requests are welcome at <https://github.com/simonsoanes/Webmail>.

## Licensing of contributions

The project is licensed under the [Apache License, Version 2.0](LICENSE). By submitting a contribution you agree that it is licensed under the same terms, as described in section 5 of the license. Don't submit code you can't license this way, and name any third-party material you include so it can be added to [NOTICE](NOTICE).

New source files start with the standard header:

```csharp
// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
```

(`@* ... *@` in Razor files, `/* ... */` in CSS.)

## Before opening a pull request

```bash
dotnet test
cd tests/pgp && npm ci && npm test     # needs GnuPG 2.2+ on PATH
```

- Keep pull requests focused on one change, and add tests for new behaviour.
- The application only references Microsoft packages. Please discuss new dependencies in an issue first.
- Never commit a database, data protection keys or real credentials. `.gitignore` covers the default `data` folder.
