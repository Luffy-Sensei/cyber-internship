#!/usr/bin/env python3

"""
Day 11 - Social Engineering Awareness Training Module

CodingAtom Cybersecurity Internship - Phase 1

A defensive CLI training tool that presents scenario-based
social-engineering questions, provides immediate feedback,
calculates an awareness score, and saves the results.

This program is designed for authorized security-awareness
training only.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_QUESTIONS = BASE_DIR / "input" / "questions.json"
DEFAULT_JSON_OUTPUT = BASE_DIR / "output" / "quiz_results.json"
DEFAULT_TXT_OUTPUT = BASE_DIR / "output" / "quiz_results.txt"
LOG_FILE = BASE_DIR / "output" / "quiz.log"


def setup_logging() -> logging.Logger:
    """Configure application logging."""

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler()
        ]
    )

    return logging.getLogger("se_awareness_quiz")


logger = setup_logging()


def load_questions(path: Path) -> List[Dict[str, Any]]:
    """Load and validate quiz questions from JSON."""

    if not path.exists():
        raise FileNotFoundError(f"Question file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in question file: {exc}"
        ) from exc

    if not isinstance(data, list) or not data:
        raise ValueError("Question file must contain a non-empty JSON list.")

    required_fields = {
        "id",
        "category",
        "difficulty",
        "question",
        "options",
        "answer",
        "explanation"
    }

    for index, question in enumerate(data, start=1):
        if not isinstance(question, dict):
            raise ValueError(
                f"Question {index} must be a JSON object."
            )

        missing = required_fields - question.keys()

        if missing:
            raise ValueError(
                f"Question {index} is missing fields: "
                f"{', '.join(sorted(missing))}"
            )

        options = question["options"]

        if not isinstance(options, dict):
            raise ValueError(
                f"Question {index}: options must be an object."
            )

        if set(options.keys()) != {"A", "B", "C"}:
            raise ValueError(
                f"Question {index}: options must contain A, B and C."
            )

        answer = str(question["answer"]).upper()

        if answer not in {"A", "B", "C"}:
            raise ValueError(
                f"Question {index}: answer must be A, B or C."
            )

        question["answer"] = answer

    return data


def get_answer(options: Dict[str, str]) -> str:
    """Prompt the user until a valid answer is entered."""

    while True:
        answer = input("\nYour answer (A/B/C): ").strip().upper()

        if answer in options:
            return answer

        print("Invalid choice. Please enter A, B, or C.")


def get_awareness_level(score: int, total: int) -> str:
    """Return an awareness classification based on percentage."""

    if total == 0:
        return "Not Assessed"

    percentage = (score / total) * 100

    if percentage >= 90:
        return "Excellent"
    if percentage >= 70:
        return "Good"
    if percentage >= 50:
        return "Needs Improvement"

    return "High Training Need"


def print_banner() -> None:
    """Display the application banner."""

    print("\n" + "=" * 72)
    print("🛡️  DAY 11 — SOCIAL ENGINEERING AWARENESS TRAINING")
    print("=" * 72)
    print("Scenario-based defensive security awareness quiz")
    print("CodingAtom Cybersecurity Internship — Phase 1")
    print("=" * 72)


def run_quiz(
    questions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Run the interactive awareness quiz."""

    score = 0
    answers: List[Dict[str, Any]] = []

    print_banner()

    print("\nTraining instructions:")
    print("- Read each scenario carefully.")
    print("- Choose the safest defensive response.")
    print("- You will receive immediate feedback.")
    print("- Your final score will be saved to the output directory.")

    input("\nPress Enter to begin...")

    for number, question in enumerate(questions, start=1):
        print("\n" + "-" * 72)
        print(
            f"Question {number}/{len(questions)}"
            f" | Category: {question['category']}"
            f" | Difficulty: {question['difficulty']}"
        )
        print("-" * 72)

        print(f"\n{question['question']}\n")

        for option, text in question["options"].items():
            print(f"  {option}) {text}")

        user_answer = get_answer(question["options"])
        correct_answer = question["answer"]

        correct = user_answer == correct_answer

        if correct:
            score += 1
            print("\n✓ Correct!")
        else:
            print(
                f"\n✗ Incorrect. "
                f"The safest answer is {correct_answer}."
            )

        print(f"\nWhy: {question['explanation']}")

        answers.append(
            {
                "question_id": question["id"],
                "category": question["category"],
                "difficulty": question["difficulty"],
                "selected_answer": user_answer,
                "correct_answer": correct_answer,
                "correct": correct
            }
        )

    total = len(questions)
    percentage = round((score / total) * 100, 2)
    awareness_level = get_awareness_level(score, total)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_questions": total,
        "correct_answers": score,
        "incorrect_answers": total - score,
        "score_percentage": percentage,
        "awareness_level": awareness_level,
        "answers": answers
    }

    return result


def save_json(result: Dict[str, Any], path: Path) -> None:
    """Save quiz results as JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    logger.info("JSON report saved to: %s", path)


def save_text(result: Dict[str, Any], path: Path) -> None:
    """Save quiz results as human-readable text."""

    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "DAY 11 — SOCIAL ENGINEERING AWARENESS TRAINING",
        "=" * 60,
        "",
        f"Timestamp          : {result['timestamp']}",
        f"Total Questions    : {result['total_questions']}",
        f"Correct Answers    : {result['correct_answers']}",
        f"Incorrect Answers  : {result['incorrect_answers']}",
        f"Score              : {result['score_percentage']}%",
        f"Awareness Level    : {result['awareness_level']}",
        "",
        "QUESTION RESULTS",
        "-" * 60
    ]

    for index, answer in enumerate(result["answers"], start=1):
        status = "CORRECT" if answer["correct"] else "INCORRECT"

        lines.extend(
            [
                "",
                f"Question {index}",
                f"Category           : {answer['category']}",
                f"Difficulty         : {answer['difficulty']}",
                f"Selected Answer    : {answer['selected_answer']}",
                f"Correct Answer     : {answer['correct_answer']}",
                f"Result             : {status}"
            ]
        )

    lines.extend(
        [
            "",
            "=" * 60,
            "Training complete."
        ]
    )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    logger.info("Text report saved to: %s", path)


def print_summary(result: Dict[str, Any]) -> None:
    """Display final quiz summary."""

    print("\n" + "=" * 72)
    print("FINAL AWARENESS ASSESSMENT")
    print("=" * 72)

    print(
        f"Score           : "
        f"{result['correct_answers']}/"
        f"{result['total_questions']}"
    )

    print(f"Percentage      : {result['score_percentage']}%")
    print(f"Awareness Level : {result['awareness_level']}")

    print("=" * 72)

    if result["awareness_level"] == "Excellent":
        print("Excellent awareness. Continue applying these defensive habits.")
    elif result["awareness_level"] == "Good":
        print("Good awareness. Review the scenarios you missed.")
    elif result["awareness_level"] == "Needs Improvement":
        print("Additional awareness training is recommended.")
    else:
        print(
            "High training need identified. "
            "Review the scenarios and repeat the assessment."
        )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Day 11 social-engineering awareness quiz."
    )

    parser.add_argument(
        "--questions",
        default=str(DEFAULT_QUESTIONS),
        help="Path to the questions JSON file."
    )

    parser.add_argument(
        "--json-output",
        default=str(DEFAULT_JSON_OUTPUT),
        help="Path for the JSON results file."
    )

    parser.add_argument(
        "--text-output",
        default=str(DEFAULT_TXT_OUTPUT),
        help="Path for the text results file."
    )

    return parser.parse_args()


def main() -> int:
    """Application entry point."""

    args = parse_arguments()

    questions_path = Path(args.questions)
    json_output = Path(args.json_output)
    text_output = Path(args.text_output)

    try:
        logger.info("Starting social-engineering awareness quiz")
        logger.info("Question file: %s", questions_path)

        questions = load_questions(questions_path)

        logger.info("Loaded %d questions", len(questions))

        result = run_quiz(questions)

        save_json(result, json_output)
        save_text(result, text_output)

        print_summary(result)

        print(f"\n[+] JSON report: {json_output}")
        print(f"[+] Text report: {text_output}")
        print("\n✓ Training session completed successfully.")

        return 0

    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    except ValueError as exc:
        logger.error("%s", exc)
        return 1

    except KeyboardInterrupt:
        print("\n\n[!] Quiz interrupted by user.")
        return 130

    except EOFError:
        print("\n\n[!] Input stream closed.")
        return 1

    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
