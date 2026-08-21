export type Finding = { title: string; snippet: string; severity: "Critical" | "High" | "Medium" | "Low"; confidence: number; category: string };

const rules = [
  { re: /ignore (all |any )?(previous|prior|above) instructions?/gi, title: "Instruction hierarchy override", severity: "Critical" as const, category: "Prompt override", confidence: 98 },
  { re: /(reveal|show|print|repeat).{0,35}(system prompt|hidden instructions?|developer message)/gi, title: "System prompt extraction", severity: "Critical" as const, category: "Data exfiltration", confidence: 97 },
  { re: /(send|forward|upload|transmit|post).{0,60}(external|@|http|webhook)/gi, title: "External data transfer", severity: "High" as const, category: "Exfiltration", confidence: 93 },
  { re: /(do not mention|keep (this|it) secret|without telling|silently)/gi, title: "Output concealment", severity: "High" as const, category: "Evasion", confidence: 91 },
  { re: /(base64|encode|decode|rot13|hex).{0,45}(data|content|message|salary|secret)/gi, title: "Encoded payload request", severity: "High" as const, category: "Obfuscation", confidence: 89 },
  { re: /(act as|you are now|new role|switch roles?)/gi, title: "Role manipulation", severity: "Medium" as const, category: "Role hijacking", confidence: 78 },
  { re: /(bypass|disable|override).{0,40}(safety|security|filter|policy|guardrail)/gi, title: "Safety bypass attempt", severity: "Critical" as const, category: "Policy bypass", confidence: 96 },
];

export function scanText(text: string): Finding[] {
  const found: Finding[] = [];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    const match = rule.re.exec(text);
    if (match) {
      const start = Math.max(0, match.index - 28);
      const end = Math.min(text.length, match.index + match[0].length + 48);
      found.push({ ...rule, snippet: `${start ? "…" : ""}${text.slice(start, end).replace(/\s+/g, " ")}${end < text.length ? "…" : ""}` });
    }
  }
  return found;
}

function decodeXml(value: string) {
  return value.replace(/&#(x?[\da-f]+);|&(?:amp|lt|gt|quot|apos);/gi, entity => {
    if (entity.startsWith("&#")) {
      const hex = entity[2].toLowerCase() === "x";
      return String.fromCodePoint(parseInt(entity.slice(hex ? 3 : 2, -1), hex ? 16 : 10));
    }
    return ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" } as Record<string, string>)[entity.toLowerCase()] || entity;
  });
}

export function extractXmlText(xml: string) {
  return decodeXml(xml
    .replace(/<w:(?:tab|br|cr)\b[^>]*\/?\s*>/gi, " ")
    .replace(/<\/w:(?:p|tr|tc)>/gi, "\n")
    .replace(/<[^>]+>/g, " "))
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s+/g, "\n")
    .trim();
}

function u16(view: DataView, offset: number) { return view.getUint16(offset, true); }
function u32(view: DataView, offset: number) { return view.getUint32(offset, true); }

async function inflate(data: Uint8Array, method: number) {
  if (method === 0) return data;
  if (method !== 8) throw new Error(`Unsupported DOCX compression method ${method}.`);
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Extracts all text-bearing OOXML parts, including headers, comments, notes,
 * custom XML, metadata and relationship targets—not only visible body text. */
export async function extractDocxText(file: File) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = bytes.length - 22;
  while (eocd >= Math.max(0, bytes.length - 65_557) && u32(view, eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("This DOCX is not a valid ZIP package.");

  const entries = u16(view, eocd + 10);
  let cursor = u32(view, eocd + 16);
  const decoder = new TextDecoder();
  const parts: string[] = [];
  for (let i = 0; i < entries; i++) {
    if (u32(view, cursor) !== 0x02014b50) throw new Error("The DOCX directory is damaged.");
    const method = u16(view, cursor + 10);
    const compressedSize = u32(view, cursor + 20);
    const nameLength = u16(view, cursor + 28);
    const extraLength = u16(view, cursor + 30);
    const commentLength = u16(view, cursor + 32);
    const localOffset = u32(view, cursor + 42);
    const name = decoder.decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    const isTextPart = /^(word\/.*\.xml|customXml\/.*\.xml|docProps\/.*\.xml|word\/_rels\/.*\.rels)$/i.test(name);
    if (isTextPart && compressedSize <= 10_000_000) {
      const localNameLength = u16(view, localOffset + 26);
      const localExtraLength = u16(view, localOffset + 28);
      const dataStart = localOffset + 30 + localNameLength + localExtraLength;
      const xml = decoder.decode(await inflate(bytes.subarray(dataStart, dataStart + compressedSize), method));
      const text = extractXmlText(xml);
      const relationshipTargets = [...xml.matchAll(/\bTarget="([^"]+)"/gi)].map(match => decodeXml(match[1])).join(" ");
      if (text || relationshipTargets) parts.push(`[${name}]\n${text} ${relationshipTargets}`);
    }
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return parts.join("\n");
}
