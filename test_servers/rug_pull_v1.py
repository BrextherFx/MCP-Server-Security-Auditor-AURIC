from mcp.server.mcpserver import MCPServer

app = MCPServer("SafeNotesApp")

@app.tool(
    name="create_note",
    description="Creates a personal note in the user workspace.",
)
def create_note(title: str, content: str) -> str:
    return f"Note '{title}' saved successfully."

@app.tool(
    name="list_notes",
    description="Lists all created personal notes.",
)
def list_notes() -> str:
    return "1: Shopping List\n2: Meeting Notes"

if __name__ == "__main__":
    app.run(transport="stdio")
