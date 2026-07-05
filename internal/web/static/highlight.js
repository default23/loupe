// Tiny self-contained syntax highlighter for JSON and XML. No dependencies.
// Applies to <pre data-lang="json|xml"> elements on load. Content is read from
// textContent (already HTML-escaped by the server) and re-escaped here, so
// setting innerHTML is safe from injection.
(function () {
  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function hlJSON(code) {
    return esc(code).replace(
      /"(?:\\.|[^\\"])*"\s*:?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?/g,
      function (m) {
        var cls = "json-num";
        if (m.charAt(0) === '"') {
          cls = /:\s*$/.test(m) ? "json-key" : "json-str";
        } else if (m === "true" || m === "false") {
          cls = "json-bool";
        } else if (m === "null") {
          cls = "json-null";
        }
        return '<span class="' + cls + '">' + m + "</span>";
      }
    );
  }

  function hlXML(code) {
    code = esc(code);
    // Comments.
    code = code.replace(/&lt;!--[\s\S]*?--&gt;/g, function (m) {
      return '<span class="xml-comment">' + m + "</span>";
    });
    // Processing instructions / declarations, e.g. <?xml ... ?>.
    code = code.replace(/&lt;\?[\s\S]*?\?&gt;/g, function (m) {
      return '<span class="xml-punc">' + m + "</span>";
    });
    // Element tags with attributes.
    code = code.replace(
      /(&lt;\/?)([\w:.\-]+)((?:\s+[\w:.\-]+(?:="[^"]*")?)*)(\s*\/?&gt;)/g,
      function (m, open, name, attrs, close) {
        var a = attrs.replace(
          /([\w:.\-]+)(=)("[^"]*")/g,
          '<span class="xml-attr">$1</span>$2<span class="xml-attrval">$3</span>'
        );
        return (
          '<span class="xml-punc">' + open + "</span>" +
          '<span class="xml-name">' + name + "</span>" +
          a +
          '<span class="xml-punc">' + close + "</span>"
        );
      }
    );
    return code;
  }

  function hlJWT(code) {
    var parts = code.trim().split(".");
    var cls = ["jwt-h", "jwt-p", "jwt-s"];
    return parts
      .map(function (p, i) {
        return '<span class="' + (cls[i] || "jwt-s") + '">' + esc(p) + "</span>";
      })
      .join('<span class="jwt-dot">.</span>');
  }

  function apply() {
    var nodes = document.querySelectorAll("pre[data-lang]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var lang = el.getAttribute("data-lang");
      var txt = el.textContent;
      if (lang === "auto") {
        var t = txt.replace(/^\s+/, "");
        lang = t.charAt(0) === "{" || t.charAt(0) === "[" ? "json"
          : t.charAt(0) === "<" ? "xml" : "";
      }
      if (lang === "json") el.innerHTML = hlJSON(txt);
      else if (lang === "xml") el.innerHTML = hlXML(txt);
      else if (lang === "jwt") el.innerHTML = hlJWT(txt);
      el.classList.add("hl");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", apply);
  } else {
    apply();
  }

  // Re-highlight content swapped in by HTMX (e.g. the Tools live readout).
  // apply() reads textContent, so re-running over already-highlighted nodes is
  // idempotent; we only need it to reach the newly inserted <pre> elements.
  document.addEventListener("htmx:afterSwap", apply);

  // Expose for manual re-runs if ever needed.
  window.Highlight = { apply: apply };
})();
