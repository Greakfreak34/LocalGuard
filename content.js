(() => {
  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const MAX_PDF_PAGES = 100;
  const MAX_EXTRACTED_TEXT_CHARACTERS = 1000000;
  const MAX_PASTE_CHARACTERS = 1000000;
  const SUPPORTED_EXTENSIONS = new Set(["txt", "csv", "json", "md", "pdf"]);
  const PDFJS_ROOT = "vendor/pdfjs/";
  const replayingInputs = new WeakSet();
  let pdfjsPromise = null;

  const FORMATTED_SSN_PATTERN = /\b\d{3}[- .]\d{2}[- .]\d{4}\b/;
  const UNSEPARATED_SSN_PATTERN = /\b\d{9}\b/g;
  const SSN_CONTEXT_PATTERN = /(?:\b(?:s[\s._-]*s[\s._-]*n|social[\s_-]*secur(?:ity|ty|tiy)|soc(?:ial)?[\s_-]*sec(?:urity)?)(?:[\s_-]*(?:number|no\.?))?\b|\bss[\s._-]*(?:#|no\.?))/i;
  const SHORT_SSN_TYPO_PATTERN = /\bsn\b/i;

  const detectors = [
    {
      category: "email address",
      pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i
    },
    {
      category: "phone number",
      pattern: /\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]+\d{3}[\s.-]+\d{4}\b/
    },
    {
      category: "API key",
      pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b/
    }
  ];

  window.addEventListener(
    "change",
    async (event) => {
      const input = event.target;

      if (!(input instanceof HTMLInputElement) || input.type !== "file") {
        return;
      }

      if (replayingInputs.has(input)) {
        replayingInputs.delete(input);
        return;
      }

      const files = Array.from(input.files || []);
      if (files.length === 0) return;

      event.preventDefault();
      event.stopImmediatePropagation();

      try {
        const findings = new Set();

        for (const file of files) {
          const extension = file.name.split(".").pop().toLowerCase();

          if (!SUPPORTED_EXTENSIONS.has(extension)) {
            block(input, "This prototype scans TXT, CSV, JSON, Markdown, and PDF files only.");
            return;
          }

          if (file.size > MAX_FILE_BYTES) {
            block(input, "Files must be 5 MB or smaller.");
            return;
          }

          const text =
            extension === "pdf"
              ? await extractPdfText(file)
              : await file.text();

          for (const category of findSensitiveCategories(text)) {
            findings.add(category);
          }
        }

        if (findings.size > 0) {
          block(
            input,
            "Sensitive data detected: " + Array.from(findings).join(", ") + ".",
            files
          );
          return;
        }

        replayingInputs.add(input);
        input.dispatchEvent(new Event("change", { bubbles: true }));
      } catch (error) {
        if (error instanceof LocalGuardScanError) {
          block(input, error.message);
        } else {
          block(input, "The file could not be scanned.");
        }
      }
    },
    true
  );

  window.addEventListener(
    "paste",
    (event) => {
      const snapshot = captureEditablePasteTarget(event.target);
      if (!snapshot) return;

      const text = event.clipboardData?.getData("text/plain") || "";
      if (!text) return;

      if (text.length > MAX_PASTE_CHARACTERS) {
        event.preventDefault();
        event.stopImmediatePropagation();
        showBlockNotice("This paste is too large to scan. It remains blocked.");
        return;
      }

      const findings = findSensitiveCategories(text);
      if (findings.size === 0) return;

      event.preventDefault();
      event.stopImmediatePropagation();

      const restorePaste = createPasteRestorer(snapshot, text);
      showBlockNotice(
        "Sensitive text detected: " + Array.from(findings).join(", ") + ".",
        restorePaste,
        "Allow this paste once"
      );
    },
    true
  );

  function captureEditablePasteTarget(target) {
    const targetElement = target instanceof Element ? target : target?.parentElement;
    if (!targetElement) return null;

    const field = targetElement.closest("textarea, input");
    if (field instanceof HTMLTextAreaElement && !field.disabled && !field.readOnly) {
      return {
        kind: "field",
        element: field,
        value: field.value,
        start: field.selectionStart ?? field.value.length,
        end: field.selectionEnd ?? field.value.length
      };
    }

    if (
      field instanceof HTMLInputElement &&
      ["text", "search", "url", "tel", "email"].includes(field.type) &&
      !field.disabled &&
      !field.readOnly
    ) {
      return {
        kind: "field",
        element: field,
        value: field.value,
        start: field.selectionStart ?? field.value.length,
        end: field.selectionEnd ?? field.value.length
      };
    }

    let editor = targetElement;
    while (editor && editor !== document.documentElement) {
      if (editor.isContentEditable) {
        const selection = window.getSelection();
        const range = selection?.rangeCount ? selection.getRangeAt(0).cloneRange() : null;
        const safeRange = range && editor.contains(range.commonAncestorContainer) ? range : null;
        return {
          kind: "contenteditable",
          element: editor,
          html: editor.innerHTML,
          range: safeRange
        };
      }
      editor = editor.parentElement;
    }

    return null;
  }

  function createPasteRestorer(snapshot, text) {
    if (!snapshot || (snapshot.kind === "contenteditable" && !snapshot.range)) return null;

    return () => {
      const element = snapshot.element;
      if (!element.isConnected || element.disabled || element.readOnly) {
        return false;
      }

      try {
        element.focus();

        if (snapshot.kind === "field") {
          if (element.value !== snapshot.value) return false;
          element.setRangeText(text, snapshot.start, snapshot.end, "end");
          dispatchPasteInput(element, text);
          return true;
        }

        if (
          !snapshot.range ||
          element.innerHTML !== snapshot.html ||
          !element.contains(snapshot.range.commonAncestorContainer)
        ) {
          return false;
        }

        const selection = window.getSelection();
        if (!selection) return false;
        selection.removeAllRanges();
        selection.addRange(snapshot.range);
        snapshot.range.deleteContents();

        const textNode = document.createTextNode(text);
        snapshot.range.insertNode(textNode);
        snapshot.range.setStartAfter(textNode);
        snapshot.range.collapse(true);
        selection.removeAllRanges();
        selection.addRange(snapshot.range);
        dispatchPasteInput(element, text);
        return true;
      } catch {
        return false;
      }
    };
  }

  function dispatchPasteInput(element, text) {
    let event;
    try {
      event = new InputEvent("input", {
        bubbles: true,
        composed: true,
        inputType: "insertFromPaste",
        data: text
      });
    } catch {
      event = new Event("input", { bubbles: true });
    }
    element.dispatchEvent(event);
  }

  async function extractPdfText(file) {
    const pdfjs = await loadPdfJs();
    const data = new Uint8Array(await file.arrayBuffer());
    const loadingTask = pdfjs.getDocument({
      data,
      cMapUrl: chrome.runtime.getURL(PDFJS_ROOT + "cmaps/"),
      cMapPacked: true,
      standardFontDataUrl: chrome.runtime.getURL(PDFJS_ROOT + "standard_fonts/"),
      wasmUrl: chrome.runtime.getURL(PDFJS_ROOT + "wasm/"),
      iccUrl: chrome.runtime.getURL(PDFJS_ROOT + "iccs/"),
      isEvalSupported: false
    });

    try {
      const pdf = await loadingTask.promise;

      if (pdf.numPages > MAX_PDF_PAGES) {
        throw new LocalGuardScanError("PDFs must have 100 pages or fewer.");
      }

      const pageTexts = [];
      let totalCharacters = 0;

      for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
        const page = await pdf.getPage(pageNumber);

        try {
          const content = await page.getTextContent();
          const pageText = content.items
            .map((item) => (typeof item.str === "string" ? item.str : ""))
            .filter(Boolean)
            .join(" ");

          totalCharacters += pageText.length;
          if (totalCharacters > MAX_EXTRACTED_TEXT_CHARACTERS) {
            throw new LocalGuardScanError("PDF text exceeds the scan limit.");
          }

          pageTexts.push(pageText);
        } finally {
          page.cleanup();
        }
      }

      const text = pageTexts.join("\n");
      if (!text.trim()) {
        throw new LocalGuardScanError(
          "No selectable text was found. Scanned or image-only PDFs are blocked."
        );
      }

      return text;
    } finally {
      try {
        await loadingTask.destroy();
      } catch {
        // Cleanup should not replace the original scan result.
      }
    }
  }

  function loadPdfJs() {
    if (!pdfjsPromise) {
      pdfjsPromise = import(chrome.runtime.getURL(PDFJS_ROOT + "pdf.min.mjs"))
        .then((pdfjs) => {
          pdfjs.GlobalWorkerOptions.workerSrc = chrome.runtime.getURL(
            PDFJS_ROOT + "pdf.worker.min.mjs"
          );
          return pdfjs;
        })
        .catch((error) => {
          pdfjsPromise = null;
          throw error;
        });
    }

    return pdfjsPromise;
  }

  function findSensitiveCategories(text) {
    const findings = new Set();

    if (hasPossibleSsn(text)) {
      findings.add("possible SSN");
    }

    for (const detector of detectors) {
      if (detector.pattern.test(text)) {
        findings.add(detector.category);
      }
    }

    const cardCandidates = text.match(/\b(?:\d[ -]?){13,19}\b/g) || [];
    if (cardCandidates.some(isLuhnValid)) {
      findings.add("possible payment-card number");
    }

    return findings;
  }

  function hasPossibleSsn(text) {
    if (FORMATTED_SSN_PATTERN.test(text)) {
      return true;
    }

    for (const match of text.matchAll(UNSEPARATED_SSN_PATTERN)) {
      const start = Math.max(0, match.index - 60);
      const end = Math.min(text.length, match.index + match[0].length + 30);
      if (SSN_CONTEXT_PATTERN.test(text.slice(start, end))) {
        return true;
      }

      const shortLabelStart = Math.max(0, match.index - 12);
      const shortLabelEnd = Math.min(text.length, match.index + match[0].length + 12);
      if (SHORT_SSN_TYPO_PATTERN.test(text.slice(shortLabelStart, shortLabelEnd))) {
        return true;
      }
    }

    return false;
  }

  function isLuhnValid(candidate) {
    const digits = candidate.replace(/\D/g, "");

    if (digits.length < 13 || digits.length > 19) {
      return false;
    }

    let sum = 0;
    let doubleDigit = false;

    for (let index = digits.length - 1; index >= 0; index -= 1) {
      let digit = Number(digits[index]);

      if (doubleDigit) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      doubleDigit = !doubleDigit;
    }

    return sum % 10 === 0;
  }

  let blockNotice = null;

  function block(input, reason, filesToAllowOnce = null) {
    input.value = "";
    const onAllowOnce = filesToAllowOnce
      ? () => replayFilesOnce(input, filesToAllowOnce)
      : null;
    showBlockNotice(reason, onAllowOnce);
  }

  function replayFilesOnce(input, files) {
    try {
      const transfer = new DataTransfer();
      for (const file of files) {
        transfer.items.add(file);
      }

      input.files = transfer.files;
      replayingInputs.add(input);
      input.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    } catch {
      return false;
    }
  }

  function showBlockNotice(reason, onAllowOnce = null, allowLabel = "Allow this file once") {
    if (!blockNotice) {
      const host = document.createElement("div");
      const shadow = host.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = `
        :host {
          all: initial;
          color-scheme: light;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          position: fixed;
          z-index: 2147483647;
          right: 20px;
          bottom: 20px;
          display: block;
        }
        .panel {
          box-sizing: border-box;
          width: min(440px, calc(100vw - 40px));
          padding: 18px 20px;
          border: 1px solid #e7b8a8;
          border-radius: 14px;
          background: #fffaf7;
          color: #27211f;
          box-shadow: 0 12px 36px rgb(18 25 32 / 24%);
        }
        .heading { display: flex; align-items: center; gap: 11px; }
        .mark {
          display: grid;
          width: 30px;
          height: 30px;
          flex: 0 0 30px;
          place-items: center;
          border-radius: 50%;
          background: #a63d28;
          color: #fff;
          font-size: 18px;
          font-weight: 750;
        }
        h2 { margin: 0; font-size: 16px; line-height: 1.3; font-weight: 700; }
        p { margin: 12px 0 0; font-size: 13px; line-height: 1.5; }
        .privacy { color: #655c58; font-size: 12px; }
        .actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; margin-top: 16px; }
        button {
          padding: 8px 12px;
          border: 1px solid #a63d28;
          border-radius: 8px;
          background: #fff;
          color: #7c2d1d;
          font: inherit;
          font-size: 12px;
          font-weight: 650;
          cursor: pointer;
        }
        button:focus-visible { outline: 3px solid #2263a8; outline-offset: 2px; }
        .keep { border-color: #344a43; background: #344a43; color: #fff; }
        .allow { border-color: #a63d28; background: #fff; color: #7c2d1d; }
        .allow[hidden] { display: none; }
        @media (max-width: 520px) {
          :host { right: 10px; bottom: 10px; }
          .panel { width: calc(100vw - 20px); }
        }
      `;

      const panel = document.createElement("section");
      panel.className = "panel";
      panel.setAttribute("role", "alertdialog");
      panel.setAttribute("aria-labelledby", "localguard-title");
      panel.setAttribute("aria-describedby", "localguard-detail localguard-privacy");

      const heading = document.createElement("div");
      heading.className = "heading";
      const mark = document.createElement("span");
      mark.className = "mark";
      mark.setAttribute("aria-hidden", "true");
      mark.textContent = "!";
      const title = document.createElement("h2");
      title.id = "localguard-title";
      title.textContent = "LocalGuard found a possible risk";
      heading.append(mark, title);

      const detail = document.createElement("p");
      detail.id = "localguard-detail";
      const privacy = document.createElement("p");
      privacy.id = "localguard-privacy";
      privacy.className = "privacy";
      privacy.textContent = "LocalGuard scans content in your browser and does not send it to a LocalGuard server.";

      const actions = document.createElement("div");
      actions.className = "actions";
      const keep = document.createElement("button");
      keep.type = "button";
      keep.className = "keep";
      keep.textContent = "Keep blocked";
      keep.addEventListener("click", () => {
        host.remove();
        blockNotice = null;
      });
      const allow = document.createElement("button");
      allow.type = "button";
      allow.className = "allow";
      allow.textContent = allowLabel;
      allow.addEventListener("click", () => {
        const callback = blockNotice?.onAllowOnce;
        if (!callback) return;

        if (callback()) {
          host.remove();
          blockNotice = null;
          return;
        }

        detail.textContent = "The browser could not continue safely. This content remains blocked.";
        blockNotice.onAllowOnce = null;
        allow.hidden = true;
      });
      actions.append(keep, allow);

      panel.append(heading, detail, privacy, actions);
      shadow.append(style, panel);
      (document.documentElement || document.body).append(host);
      blockNotice = { detail, privacy, allow, onAllowOnce: null };
    }

    blockNotice.detail.textContent = reason + " The page has not received this content.";
    blockNotice.onAllowOnce = onAllowOnce;
    blockNotice.allow.textContent = allowLabel;
    blockNotice.allow.hidden = !onAllowOnce;
    blockNotice.privacy.textContent = onAllowOnce
      ? allowLabel === "Allow this paste once"
        ? "LocalGuard reads clipboard text only during this paste. If allowed, the current site receives it and may upload or process it; LocalGuard does not send it to its own server."
        : "If allowed, the current site receives this file and may upload it; LocalGuard scans it in your browser and does not send it to its own server."
      : "LocalGuard scans content in your browser and does not send it to a LocalGuard server.";
  }

  class LocalGuardScanError extends Error {}
})();
