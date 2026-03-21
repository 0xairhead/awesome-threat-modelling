# Agile Methodology & Key Terms Primer

Agile is a mindset and a set of values and principles for software development and project management. It focuses on iterative development, delivering value to customers frequently, and adapting to changing requirements through continuous collaboration.

This document serves as a reference for the core concepts of Agile, with a specific focus on terms commonly used in **Scrum** and **Kanban** (the two most popular Agile frameworks).

---

## 1. Core Agile Concepts

*   **Agile Manifesto:** A short document establishing four core values:
    1.  **Individuals and interactions** over processes and tools
    2.  **Working software** over comprehensive documentation
    3.  **Customer collaboration** over contract negotiation
    4.  **Responding to change** over following a plan
*   **Iterative & Incremental:** Developing software in small chunks (increments) over short periods (iterations) rather than attempting to deliver the entire project all at once (Waterfall).
*   **Scrum:** A highly structured Agile framework characterized by short, time-boxed iterations (Sprints) and specific roles and ceremonies.
*   **Kanban:** A continuous workflow framework focused on visualizing work, limiting "Work In Progress" (WIP), and maximizing efficiency (flow).

---

## 2. Key Agile Roles

*(These roles are specifically defined in Scrum, but are often adapted across different Agile teams)*

*   **Product Owner (PO):** The representative of the customer/business. They are responsible for maximizing the value of the product and prioritizing the work by managing the Product Backlog.
*   **Scrum Master:** The facilitator and protector of the Agile process. They coach the team on Agile practices, remove roadblocks (impediments), and ensure ceremonies are effective.
*   **Development Team (or just "The Team"):** The cross-functional group of professionals (developers, QA, designers) who do the actual work of building the product increment. They are self-organizing.

---

## 3. Work Items & Artifacts (The "What")

*   **Epic:** A large, complex body of work (like a massive feature) that is too big to be completed in a single iteration. Epics must be broken down into smaller Stories.
*   **User Story:** A small, specific piece of functionality described from the perspective of the end-user.
    *   *Standard Format:* "As a [type of user], I want [some goal] so that [some reason]."
*   **Task / Sub-task:** The technical steps required to complete a single User Story (e.g., "Update database schema," "Write unit tests").
*   **Product Backlog:** The master list of all everything that needs to be built or improved in the product (Stories, Bugs, Tech Debt). It is continuously prioritized by the Product Owner.
*   **Sprint Backlog:** The subset of items from the Product Backlog that the team commits to finishing during the current iteration (Sprint).
*   **Product Increment:** The sum of all completed, tested, and potentially releasable work product at the end of a Sprint.
*   **Bug / Defect:** Unintended behavior or a flaw in the product that needs to be fixed.

---

## 4. Key Ceremonies / Events (The "When")

*   **Sprint (or Iteration):** A fixed time-box (usually 1 to 4 weeks) during which a usable, distinct increment of software is built.
*   **Sprint Planning:** A meeting at the start of the Sprint where the PO and Team negotiate and agree on *what* will be built (Sprint Goal) and *how* it will be built (Sprint Backlog).
*   **Daily Stand-up (or Daily Scrum):** A short (15-minute) daily synchronization meeting for the Development Team. Often answers three questions: *What did I do yesterday? What will I do today? Are there any blockers?*
*   **Sprint Review (or Demo):** A meeting at the very end of the Sprint to demonstrate the completed "Working Software" to stakeholders and gather feedback.
*   **Sprint Retrospective (or "Retro"):** A team-only meeting held after the Review to reflect on *how* they worked together during the Sprint. The goal is continuous improvement (discussing what went well, what went wrong, and action items for next time).
*   **Backlog Refinement (or Grooming):** A recurring meeting to look ahead at future backlog items, ensuring they are clear, detailed, and estimated properly before they get pulled into a Sprint.

---

## 5. Important Metrics and Concepts

*   **Story Points:** An abstract unit of measure used by Agile teams to estimate the relative effort, complexity, and risk of a User Story (often using the Fibonacci sequence: 1, 2, 3, 5, 8, 13). It is *not* equal to hours.
*   **Velocity:** The average number of Story Points a team completes in a single Sprint. This helps predict how much work they can take on in future Sprints.
*   **Definition of Done (DoD):** A shared, team-wide checklist of requirements that every User Story must meet before it can be considered complete (e.g., code reviewed, unit tests passed, deployed to staging, documentation updated).
*   **Acceptance Criteria:** Specific requirements tied to an *individual* User Story. These represent the conditions that must be fulfilled to say that the specific feature behaves as the customer expected. (Often mapped directly to Gherkin scenarios).
*   **WIP Limit (Work in Progress Limit):** A concept from Kanban that restricts the maximum number of items allowed in a specific stage of the workflow (e.g., only 3 tickets allowed in "In Testing" at one time) to prevent bottlenecks.
*   **Technical Debt:** The implied cost of additional future rework caused by choosing an easy, messy, or fast solution now, instead of using a better approach that would take longer.
*   **Blocker / Impediment:** Anything that prevents a team member from making progress on their work.
