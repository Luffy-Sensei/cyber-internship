
---

# Day 05 Technical Report
## OSINT + Social Engineering — Target Profile

**Phase:** Phase 1  
**Day:** 05  
**Topic:** OSINT + Social Engineering: Build a Target Profile  
**Difficulty:** Intermediate  
**Platform:** Parrot OS  
**Language:** Python 3

---

## 1. Objective

The objective of Day 05 was to understand how publicly available information can be aggregated into a structured target profile.

The implementation focused on GitHub public data.

The profiler collects public GitHub profile and repository metadata, analyzes observable programming languages, identifies exposure indicators, and produces structured JSON and human-readable reports.

---

## 2. Concept

Open-Source Intelligence (OSINT) involves collecting and analyzing information that is publicly available.

In a social-engineering context, attackers may combine information from multiple public sources to develop a better understanding of a target.

Potentially useful information can include:

- Name
- Role
- Organization
- Location
- Technology stack
- Public repositories
- Public professional information
- Public activity and metadata

From a defensive perspective, the same process can be used to identify unnecessary exposure and improve security awareness.

---

## 3. Implementation

The project was implemented as a Python command-line tool:

```text
github_target_profiler.py
The implementation uses the GitHub REST API to retrieve public profile and repository information.

The program accepts a GitHub username as a command-line argument.

Example:

python3 github_target_profiler.py torvalds
4. Data Collection

The profiler collects public GitHub profile information including:

Username
Name
Company
Location
Bio
Public repository count
Public gist count
Followers
Following
Account creation date
Profile URL

The tool also retrieves public repository information.

5. Repository Analysis

The profiler analyzes up to the configured repository limit.

For each repository, the following metadata is extracted:

Repository name
Description
Primary language
Stars
Forks
Fork status
Archived status
Visibility
Last update timestamp
Repository URL

This information is then used to construct a technology profile.

6. Technology Profile

The profiler counts the primary language associated with each analyzed repository.

The resulting language distribution provides an observable high-level representation of the technologies associated with the public repositories.

This should not be interpreted as a complete technology stack because repository language metadata does not necessarily represent every technology used by a project.

7. Exposure Assessment

The tool generates defensive exposure indicators.

Examples include:

Public Identity

A public display name is available.

Organizational Affiliation

A public company or organization field is available.

Location Exposure

A public location field is available.

Repository Exposure

Public repositories are observable.

Technology Exposure

Repository metadata exposes observable primary programming languages.

These indicators describe public metadata exposure and do not establish private facts about the individual.

8. Defensive Analysis

The exercise demonstrates that individually harmless pieces of information can become more useful when aggregated.

For example:

Public name
      +
Organization
      +
Location
      +
Repositories
      +
Programming languages

can provide a much broader picture than any single field provides independently.

From a defensive perspective, organizations and individuals should periodically review what information is publicly visible and whether every published field is necessary.

9. Defensive Recommendations

Recommended defensive practices include:

Review publicly visible profile information.
Remove unnecessary organizational or location information.
Review public repositories for accidental sensitive information.
Never publish passwords, API keys, authentication tokens, or private keys.
Review repository descriptions and metadata.
Use secret-scanning capabilities where appropriate.
Review public technology information as part of broader exposure assessments.
Minimize unnecessary information that could assist social-engineering attempts.
10. Error Handling

The implementation includes handling for several API and network conditions.

HTTP 404

The requested GitHub resource does not exist.

HTTP 403

The request may have been rejected or the API may have reached a rate limit.

HTTP 429

The API explicitly reported a rate-limit condition.

HTTP 5xx

GitHub returned a server-side error.

Network Failure

Request exceptions are converted into controlled application errors.

Invalid JSON

Unexpected or invalid API responses are handled as application errors.

11. Output

The implementation generates two reports.

Structured JSON
output/target_profile.json

The JSON report is suitable for further processing, analysis, or integration into other security tooling.

Human-Readable Report
output/target_profile.txt

The text report provides a concise human-readable summary of the collected profile and exposure assessment.

12. Evidence

The following screenshots document the implementation:

Scanner Execution
screenshots/scanner-execution.png

Shows the profiler executing against the selected GitHub username.

Target Profile
screenshots/target-profile.png

Shows the generated target profile information.

Technology Profile
screenshots/technology-profile.png

Shows the programming-language analysis.

JSON Report
screenshots/json-report.png

Shows the structured JSON output.

13. Validation

The generated JSON report was validated using:

jq empty output/target_profile.json

Python syntax can be validated using:

python3 -m py_compile github_target_profiler.py

Repository whitespace was checked using:

git diff --check
14. Limitations

The implementation has several limitations.

GitHub Rate Limits

Unauthenticated GitHub API requests are subject to API rate limits.

Repository Language Metadata

GitHub's primary language field does not represent every technology used by a repository.

Repository Limit

The profiler analyzes a configured number of repositories rather than attempting unrestricted collection.

Public Data Only

The tool does not access private repositories, private profile information, or authentication-protected resources.

OSINT Context

The collected information represents what was publicly observable at the time of collection.

15. Key Lessons

Day 05 demonstrated how OSINT can be transformed from individual observations into a structured target profile.

The most important lesson was that exposure should be evaluated collectively rather than field-by-field.

Public identity information, organizational information, location, repositories, and technology metadata can collectively reveal considerably more information than any individual field.

For defenders, understanding this aggregation process helps identify unnecessary public exposure and improve security-awareness practices.

16. Conclusion

The Day 05 OSINT target-profile aggregator successfully collected publicly available GitHub information and converted it into structured and human-readable reports.

The project demonstrated:

GitHub API interaction
Public OSINT collection
Repository metadata analysis
Technology profiling
Exposure assessment
Defensive OSINT analysis
JSON report generation
Human-readable report generation
API error handling

The resulting tool provides a foundation for understanding how public digital footprints can be assessed from a defensive cybersecurity perspective.
