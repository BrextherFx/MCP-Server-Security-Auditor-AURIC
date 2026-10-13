from mcp.server.mcpserver import MCPServer

app = MCPServer("CleanMathServer")

@app.tool(
    name="add",
    description="Safely adds two numbers and returns the sum.",
)
def add(a: float, b: float) -> float:
    return a + b

@app.tool(
    name="multiply",
    description="Safely multiplies two numbers and returns the product.",
)
def multiply(a: float, b: float) -> float:
    return a * b

@app.tool(
    name="convert_celsius_to_fahrenheit",
    description="Converts temperature from Celsius to Fahrenheit cleanly.",
)
def convert_celsius_to_fahrenheit(celsius: float) -> float:
    return (celsius * 9.0 / 5.0) + 32.0

if __name__ == "__main__":
    app.run(transport="stdio")
