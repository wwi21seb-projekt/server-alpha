# Development Guidelines

This document outlines the development guidelines for our project, focusing on coding standards, Git workflow, project structure, and logging practices.

## Code Style Guidelines

- Indentation: Use 4 spaces.
- Line Length: Limit lines to 80 characters.
- Formatting: Adhere to the official Go formatting guidelines using `gofmt`.
- Use `golint` to check for style errors.
- Use `go vet` to check for suspicious constructs.

## Naming Conventions

- Variables and Functions: Use camelCase.
- Exported (public) names: Use PascalCase.
- Descriptive Naming: Avoid abbreviations; use clear, descriptive names.

## Go Idioms

- Favor composition over inheritance.
- Define behavior with interfaces.
- Use goroutines and channels for concurrency.
- Employ the `defer` statement for resource cleanup.

## Documentation

- Document all exported entities (functions, types, variables).
- Use GoDoc format for comments.
- Include examples in documentation where necessary.
- Keep documentation current as code evolves.

## Testing

- Verify new API endpoints with tests.
- Cover positive and negative scenarios.
- Include contract tests for API request/response validation.

## Clean Code Principles

1. DRY (Don't Repeat Yourself): Avoid code duplication.
2. Single Responsibility Principle: One function/method, one responsibility.
3. Meaningful Names: Choose self-explanatory names.
4. Small Functions: Aim for concise functions with a focused purpose.
5. Explicit Error Handling: Check and handle errors; no silent failures.
6. Code Readability: Write easily understandable code, following Go idioms.
7. Testability: Write testable code, consider dependency injection.

## Git Workflow

- Use feature branches for development.
- Create pull requests for code review.
- Write clear, concise pull request descriptions.
- Squash commits for a clean history.

## Project Structure Guidelines

### /cmd

- Contains main applications for the project.
- Each subdirectory represents an executable (e.g., `/cmd/server`).

### /internal

- For private code, not imported by other projects.
- Organize shared and private code within `/internal/app` and `/internal/pkg`.

### /pkg

- Library code meant for external use.
- Ensure code in `/pkg` is well-documented and stable.

### /api

- Houses OpenAPI/Swagger specs and protocol definition files.

### /configs

- Contains configuration file templates or default configs.

### /deployments

- Deployment configurations for various platforms.

### /docs

- Design documents, user guides, and other documentation.

### /scripts

- Scripts for building, installing, and code analysis.

### /build

- Packaging and Continuous Integration configurations and scripts.

## Logging Guidelines with Grafana Loki

In our project, we utilize Grafana Loki for logging. Here are the detailed guidelines to ensure effective and consistent logging practices:

- **Log Levels:**
  - Utilize standardized log levels to categorize log messages:
    - `DEBUG` for detailed diagnostic information.
    - `INFO` for general operational messages.
    - `WARN` for potential issues that don't require immediate action.
    - `ERROR` for error events that might still allow the application to continue running.
    - `FATAL` for severe error events that lead the application to abort.
-
- **Structured Logging:**
  - Implement structured logging to create log entries in a consistent, machine-readable format like JSON.
  - This approach facilitates easier querying and analysis of log data within Grafana.
- **Grafana Dashboards:**
  - Design and utilize Grafana dashboards for visualizing and analyzing log data.
  - Create dashboards that allow for easy identification of trends, anomalies, and critical events.
- **Alerts and Notifications:**
  - Set up alerts in Grafana based on specific log patterns or anomalies that indicate potential issues or system failures.
  - Use Grafana's notification channels to ensure the right team members are alerted in case of critical events.
- **Efficient Use of Loki:**
  - Optimize Loki's configuration for efficient log ingestion and storage.
  - Regularly review and adjust Loki's retention policies to balance between log availability and resource utilization.
- **Consistent Logging Practices:**
  - Ensure all developers follow these logging guidelines to maintain consistency across the project.
  - Regularly review and update the logging practices to adapt to the evolving needs of the project.

Adhering to these logging guidelines will help us in maintaining a robust and scalable logging system, facilitating effective monitoring, debugging, and operational analysis.
