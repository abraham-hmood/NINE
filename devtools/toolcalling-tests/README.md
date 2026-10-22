Off-device tests for the tool-calling pipeline (JVM, no Android needed).
Needs kotlinc + org.json (stleary/JSON-java) on the classpath.
- ParserTest.kt : compile with ToolCallParser.kt + AiModels.kt, run com.nine.dbt.TestKt
- E2E.kt + server.py : mock OpenAI-compatible server; compile with CloudClient.kt, ToolExecutor.kt,
  ToolCallParser.kt, AiModels.kt, Stubs.kt, Stubs2.kt; start `python3 server.py`, run com.nine.dbt.E2EKt
