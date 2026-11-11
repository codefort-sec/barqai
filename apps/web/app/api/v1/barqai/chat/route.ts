import { NextRequest, NextResponse } from "next/server";
import { synthesizeBarqAIChatResponse, BarqAIChatRequest } from "@/lib/barqai_engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body: BarqAIChatRequest = await req.json();

    // 1. If backend API is reachable at process.env.BACKEND_API_URL or http://localhost:8000, attempt proxy
    const backendUrl = process.env.BACKEND_API_URL || "http://localhost:8000";
    if (backendUrl && !backendUrl.includes("codefort-lilac.vercel.app")) {
      try {
        const proxyRes = await fetch(`${backendUrl}/api/v1/barqai/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(3000),
        });
        if (proxyRes.ok) {
          const data = await proxyRes.json();
          return NextResponse.json(data);
        }
      } catch {
        // Fall through to internal BARQAI synthesis engine
      }
    }

    // 2. If OPENROUTER_API_KEY is available in the environment, attempt Qwen MoE
    const openrouterKey = process.env.OPENROUTER_API_KEY;
    if (openrouterKey) {
      try {
        const prompt = `User prompt: ${body.message}\nError Context: ${body.error_context || "None"}\nCode Snippet: ${body.code_snippet || "None"}`;
        const llmRes = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${openrouterKey}`,
            "HTTP-Referer": "https://codefort.sec",
            "X-Title": "CodeFort BARQAI",
          },
          body: JSON.stringify({
            model: "qwen/qwen-2.5-coder-32b-instruct",
            messages: [
              {
                role: "system",
                content:
                  "You are BARQAI, the AI cybersecurity intelligence and code remediation copilot of CODEFORT.\n" +
                  "You reply naturally to greetings (hi, hello) and answer questions about software projects, GitHub repositories, pull requests, CI/CD security, and developer workflows.\n" +
                  "When the user asks conversational or conceptual questions without providing buggy code or asking for code rewrite, provide an articulate, expert response and set rewritten_code to null.\n" +
                  "When the user provides an error, stack trace, or asks to rewrite/fix code, explain the root cause and provide clean rewritten code.\n" +
                  "Return JSON with: {\"reply\": \"...\", \"explanation\": \"...\", \"rewritten_code\": null or \"...\"}",
              },
              { role: "user", content: prompt },
            ],
            temperature: 0.2,
          }),
          signal: AbortSignal.timeout(5000),
        });

        if (llmRes.ok) {
          const llmData = await llmRes.json();
          const rawContent = llmData.choices?.[0]?.message?.content || "";
          try {
            const cleanJson = rawContent.replace(/```json|```/g, "").trim();
            const parsed = JSON.parse(cleanJson);
            const rewritten =
              parsed.rewritten_code &&
              parsed.rewritten_code !== "null" &&
              parsed.rewritten_code.trim() !== ""
                ? parsed.rewritten_code
                : undefined;
            const explanationText =
              parsed.explanation ||
              (parsed.reply && parsed.reply !== parsed.rewritten_code ? parsed.reply : null) ||
              rawContent.split("```")[0].trim() ||
              rawContent;

            return NextResponse.json({
              reply: parsed.reply || rawContent,
              explanation: explanationText,
              rewritten_code: rewritten,
              original_code: rewritten ? body.code_snippet : undefined,
              diff: parsed.diff || undefined,
              model: "Qwen 2.5 Coder 32B Instruct (MoE)",
              suggested_actions: rewritten
                ? ["Explain root cause in depth", "Show unified git diff", "Investigate suspicious threat vectors"]
                : ["How do pull requests work?", "How to secure a GitHub repository", "Explain GitHub Actions security"],
            });
          } catch {
            const hasCode = Boolean(body.code_snippet || body.error_context);
            const codeMatch = hasCode ? rawContent.match(/```(?:\w+)?\n([\s\S]*?)```/) : null;
            const explanationText = codeMatch ? rawContent.split("```")[0].trim() : rawContent;
            const rewritten = codeMatch ? codeMatch[1].trim() : undefined;
            return NextResponse.json({
              reply: rawContent,
              explanation: explanationText,
              rewritten_code: rewritten,
              original_code: rewritten ? body.code_snippet : undefined,
              model: "Qwen 2.5 Coder 32B Instruct (MoE)",
              suggested_actions: rewritten
                ? ["Explain root cause in depth", "Show unified git diff", "Investigate suspicious threat vectors"]
                : ["How do pull requests work?", "How to secure a GitHub repository", "Explain GitHub Actions security"],
            });
          }
        }
      } catch {
        // Fall through to deterministic engine
      }
    }

    // 3. Fallback to resilient deterministic BARQAI synthesis (100% Guaranteed 200 OK)
    const result = synthesizeBarqAIChatResponse(body);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: { message: err?.message || "Internal chat error", code: "CHAT_ERROR" } },
      { status: 500 }
    );
  }
}
