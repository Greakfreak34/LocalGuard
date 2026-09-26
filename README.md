# LocalGuard

LocalGuard is a Chrome Manifest V3 prototype that checks supported files and pasted text in the browser before a supported AI site receives them.

## Features

- Checks TXT, CSV, JSON, Markdown, and searchable PDF files selected through a file picker.
- Checks text during a user-initiated paste into supported editable fields.
- Looks for possible Social Security numbers, email addresses, formatted US phone numbers, Luhn-valid payment-card numbers, and selected API-key formats.
- Blocks detected content by default. The user can keep it blocked or allow that file or paste once.
- Shows finding categories without displaying the matched values.
- Scans locally in the browser. LocalGuard has no server that receives or stores file or clipboard contents.

The extension currently targets ChatGPT (`chatgpt.com` and `chat.openai.com`) and Claude (`claude.ai`).

## Install in Chrome

1. Download or clone this repository.
2. Open `chrome://extensions` and turn on **Developer mode**.
3. Select **Load unpacked** and choose the LocalGuard folder containing `manifest.json`.
4. Refresh any ChatGPT or Claude tabs that were already open.

To use the included local test page, open LocalGuard's **Details** page and enable **Allow access to file URLs**, then open `test.html` in Chrome.

## Manual checks

The repository includes synthetic clean and sensitive TXT, JSON, and PDF samples. On `test.html`, choose a clean sample to confirm it passes, then a sensitive sample to confirm LocalGuard blocks it. The page also has a text field for checking paste protection.

You can repeat the checks on ChatGPT or Claude with synthetic content. If you choose the one-time allow option, the site may receive the content; do not submit a message during a privacy check. Never use real personal information in the samples or test prompts.

## Privacy and limitations

File and pasted text are inspected in the browser. Clipboard text is read only when the user initiates a paste; LocalGuard does not monitor clipboard history. The extension does not send content to a LocalGuard server. If the user allows content, the current AI site may upload or process it under that site's own policies.

Detection uses patterns, so it can miss sensitive information or flag ordinary text. Formatted SSNs are checked directly; a 9-digit value without separators is flagged when an SSN-related label appears nearby. The short `SN` label is also accepted and may refer to a serial number.

The prototype does not scan manually typed text, images, scanned or image-only PDFs, or drag-and-drop uploads. It blocks unsupported files and content that cannot be scanned. File uploads are limited to 5 MB; PDFs are limited to 100 pages and 1 million extracted text characters; pastes are limited to 1 million characters.

## PDF.js

PDF text extraction uses the bundled PDF.js 6.3.289 files in `vendor/pdfjs`. The extension does not load PDF.js from a CDN. The upstream PDF.js and related component licenses are included with the bundled files.