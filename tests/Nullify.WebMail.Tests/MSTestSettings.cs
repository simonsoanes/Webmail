// Serial execution: the integration tests boot a WebApplicationFactory host whose
// startup runs EnsureCreated against SQLite — parallel host builds race on CREATE TABLE.
[assembly: Parallelize(Workers = 1, Scope = ExecutionScope.MethodLevel)]