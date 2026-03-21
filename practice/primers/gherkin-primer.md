# Gherkin Language Primer

Gherkin is a plain-text language with a simple structure. It is designed to be easy to learn by non-programmers, yet structured enough to allow concise description of examples to illustrate business rules in most real-world domains. It is the primary language used by tools like Cucumber, Behave, and SpecFlow for Behavior-Driven Development (BDD).

Gherkin serves two main purposes:
1.  **Documentation:** Serving as project documentation and defining the "living specification."
2.  **Automated Testing:** Acting as the skeleton for automated acceptance tests.

## 1. Core Keywords

Gherkin relies on a set of specific keywords to structure its documents (usually saved as `.feature` files).

### Feature
The `Feature` keyword is used to describe a high-level software feature, and to group related scenarios. It is the first primary keyword in a Gherkin document.

```gherkin
Feature: User Login
  As a registered user
  I want to log into my account
  So that I can access my dashboard
```

### Scenario
A `Scenario` is a concrete example that illustrates a business rule. It describes a specific situation and the expected outcome. A feature file can contain multiple scenarios.

```gherkin
Scenario: Successful login with valid credentials
```

### Given, When, Then (The Steps)
These are the most important keywords, used to describe the state, action, and outcome of a scenario.

*   **Given:** Describes the initial context or past state of the system before the user takes the main action. It's like the setup or prerequisites.
*   **When:** Describes the main action the user (or external system) takes.
*   **Then:** Describes the expected outcome or observable result of that action.

```gherkin
Scenario: Successful login with valid credentials
  Given the user is on the login page
  When the user enters valid credentials
  Then the user should be redirected to the dashboard
```

### And, But
If you have multiple contiguous `Given`, `When`, or `Then` steps, you can use `And` or `But` to make the scenario more readable instead of repeating the keyword.

```gherkin
Scenario: Unsuccessful login with multiple errors
  Given the user is on the login page
  And the user's account is locked
  When the user attempts to log in
  Then an "Account Locked" error should be displayed
  But the password reset fields should be hidden
```

---

## 2. Advanced Keywords

### Background
If all scenarios in a feature share the same initial setup (`Given` steps), you can use a `Background` to avoid repeating them. A background runs *before* each scenario in the feature.

```gherkin
Feature: Shopping Cart Management

  Background:
    Given a logged-in user exists
    And the user has an empty shopping cart

  Scenario: Adding an item to the cart
    When the user adds a "Laptop" to the cart
    Then the cart should contain 1 item

  Scenario: Removing an item from the cart
    Given the user has added a "Mouse" to the cart
    When the user removes the "Mouse" from the cart
    Then the cart should be empty
```

### Scenario Outline & Examples
When you have a scenario that needs to be tested with multiple sets of data, use `Scenario Outline` combined with `Examples` to avoid duplicating the entire scenario. Variables are denoted by `<variable_name>`.

```gherkin
Feature: Login Validation

  Scenario Outline: Failed login attempts
    Given the user is on the login page
    When the user enters "<username>" and "<password>"
    Then the system should display the message "<error_message>"

    Examples:
      | username | password | error_message            |
      | admin    | wrongpwd | Invalid credentials      |
      |          | secret   | Username is required     |
      | user     |          | Password is required     |
      | admin    | secret   | Account is locked        |
```

---

## 3. Best Practices for Writing Gherkin

1.  **Keep it Declarative, not Imperative:** Describe *what* the system should do, not *how* it should do it. Avoid UI-specific details like "clicks the blue button with ID #submit".
    *   **Bad (Imperative):** `When the user enters "john" into the "username" field and "123" into the "password" field and clicks the "Login" button`
    *   **Good (Declarative):** `When the user logs in with valid credentials`
2.  **Focus on Business Value:** The vocabulary used should be the ubiquitous language of the business domain, understood by both developers and stakeholders.
3.  **One Action per Scenario:** Try to limit your scenarios to a single `When` step (a single action) to keep tests focused and easier to debug.
4.  **Keep Scenarios Independent:** Scenarios should not rely on each other. The order in which they run should not matter.
