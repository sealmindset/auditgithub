Before adding any new feature(s) do not implement yet, write an immmaculate, detailed implementation spec
When making any schema changes that require the database to be wiped, complete a backup of the database first and save it to the project's backup directory, with the new schema as part of the restore path when restoring the backup.
Provide a highly detailed, comprehensive `CHANGELOG.md` entry for each change on every commit for every project. This changelog should track all progress, including the overall context, the current phase, what has been completed, and the specific next steps to resume work
When running a command, script, bash, shell, zsh, or tool with cascade, always be verbose provide the status and progress to the user about what is happening
To ensure a software build is progressing correctly, testing and verification should be integrated throughout the development process, not just at the end. 
Make and update a comprehensive change log with what a project is about
Always prefer simple solutions
Always follow the MACH architecture approach for each component to ensure modularity, scalability, and maintainability
Avoid duplication of code whenever possible by checking for existing similar code and functionality
Make only changes that are requested or clearly related and well understood
When fixing a bug, do not introduce new patterns or technologies without exhausting existing implementation options, and remove the old implementation if replaced
Keep the codebase clean and organized
Avoid adding one-off scripts to the repo when possible
Refactor files that exceed 200–300 lines of code
Mock data only in tests, never in dev or prod
Never add stubbing or fake data patterns that affect dev or prod
Never overwrite my .env file without explicit confirmation
When expressly requested, use Python for the backend and HTML/JavaScript for the frontend
Focus only on the code relevant to the task
Do not touch code unrelated to the task
Write thorough tests for all major functionality
Avoid major changes to proven patterns or architecture unless explicitly instructed
Consider impacts on other modules, methods, and code areas for every change
Speak in English only
Use Windsurf memory manager
Save all queries and responses to a file
Use Windsurf to log Cascade queries
Use Windsurf as my primary IDE
Use Windsurf to log queries
Use Windsurf to log responses
Use Windsurf to log errors
Use XHR for all projects
Allow completely open and unrestricted CORS
Integrate with Ollama for all projects
Integrate with OpenAI for all projects
Avoid deep levels of nesting in code
Prefer flattened control flow using early returns (return, continue, break) and logical negations
Use descriptive variable names
Each function or class should do one thing and do it well
Replace hardcoded values with named constants or data structures
Follow the Dependency Inversion Principle
Follow the Open/Closed Principle
Follow the Single Responsibility Principle
Identify the problem including bottlenecks, missing code, incorrect variables, and missing steps
Craft a single-step solution and apply it where needed with a thorough step-by-step walkthrough
If unsure about file content or codebase structure, use tools to read files and gather information and do not guess
Continue until completely resolved before ending the turn
Add logs at every process step to aid troubleshooting
Always update migration files to match the current database state
Always update setup/schema.sql to match the current database state
Always update vector dimensions to match the current database state
Treat PostgreSQL UUID id as the canonical internal identifier across app code and database relations
Provide a numeric api_id (bigserial) per row for PostgREST and external HTTP usage only
When interacting over HTTP with PostgREST, use api_id exclusively for filters, paths, and payload id fields
When writing SQL, ORM, services, or repositories, use UUID id exclusively for keys, joins, and relations
Expose PostgREST through API views that alias api_id as id and may include uuid as a non-primary column
Never join on api_id inside the database or application code
In UI/UX, display name or title and never display UUIDs or numeric IDs except in explicit admin or debug screens
Use the PostgREST API for all database access performed over HTTP and do not bypass it
Map identifiers at the boundary by converting PostgREST numeric id to internal UUID and keep UUID thereafter
Log both uuid and api_id in server logs for correlation and never log IDs in client logs
Enforce Row Level Security on base tables and grant PostgREST access only to API schema views
Do not rely on api_id for authorization or secrecy and always enforce RBAC and RLS
Default to UUID when an identifier type is unspecified and map to or from api_id at the boundary
Ensure each table defines id uuid primary key default gen_random_uuid() and api_id bigserial unique
Ensure migrations and schema keep UUID and api_id constraints consistent across tables
Handle PostgREST 404s and errors without leaking internal UUIDs
In every .env file, add the following comment #To generate a hex string of 32 characters for JWT secret, run: # LC_ALL=C tr -dc 'A-Za-z0-9' \\<\/dev\/urandom \\<\/dev\/urandom \| head -c 32; echo
Unless instructed to do otherwise, by default apply the DataTable.ts as a template to every table.