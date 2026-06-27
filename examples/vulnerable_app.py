"""Example vulnerable LLM application - DO NOT use in production.

This file demonstrates all 6 vulnerability patterns detected by llm-seclint.
Run `llm-seclint scan examples/vulnerable_app.py` to see the findings.
"""

import os
import pickle
import sqlite3
import subprocess

import openai

# LS001: Hardcoded API key
openai.api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
ANTHROPIC_API_KEY = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"


def get_chat_response(user_input: str) -> str:
    """Get a response from the LLM."""
    # LS002: User input concatenated into prompt
    prompt = f"You are a helpful assistant. The user says: {user_input}"

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def search_database(prompt: str) -> list:
    """Search the database using an LLM-generated query value."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # The LLM's output flows into the SQL query within this function, so the
    # taint engine confirms the LLM->SQL injection (LS003, taint-gated).
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    term = response.choices[0].message.content
    # LS003: confirmed LLM output in SQL query
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return cursor.fetchall()


def execute_command(llm_response: str) -> str:
    """Execute a command suggested by the LLM."""
    # LS004: LLM output passed to shell
    result = subprocess.run(llm_response, shell=True, capture_output=True, text=True)
    return result.stdout


def read_file(llm_response: str) -> str:
    """Read a file path suggested by the LLM."""
    # LS005: LLM output used as file path
    with open(llm_response) as f:
        return f.read()


def parse_response(llm_response: str) -> dict:
    """Parse structured data from LLM response."""
    # LS006: eval on LLM response
    return eval(llm_response)


def load_cached_response(data: bytes) -> object:
    """Load a cached LLM response."""
    # LS006: pickle on potentially LLM-sourced data
    return pickle.loads(data)


def run_llm_generated_code(prompt: str) -> object:
    """Execute code the model returns — confirmed LLM->sink dataflow."""
    # LS006: the LLM's output flows through a variable into eval() within this
    # function, so the taint engine confirms the LLM->sink dataflow.
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    code = response.choices[0].message.content
    return eval(code)


def main() -> None:
    user_msg = input("Enter your message: ")
    response = get_chat_response(user_msg)
    print(f"LLM says: {response}")

    # Use LLM output in dangerous ways
    results = search_database(response)
    cmd_output = execute_command(response)
    file_content = read_file(response)
    parsed = parse_response(response)


if __name__ == "__main__":
    main()
