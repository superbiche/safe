(function () {
  function resolveUrl(baseUrl, path) {
    var base = baseUrl || ".";
    if (base === ".") {
      return path;
    }
    return base.replace(/\/$/, "") + "/" + path.replace(/^\//, "");
  }

  function text(value) {
    return (value || "").toString().toLowerCase();
  }

  function excerpt(entry, query) {
    var body = entry.text || entry.content || "";
    var lower = body.toLowerCase();
    var idx = lower.indexOf(query.toLowerCase());
    if (idx < 0) {
      return body.slice(0, 140);
    }
    var start = Math.max(0, idx - 50);
    var end = Math.min(body.length, idx + query.length + 90);
    return (start > 0 ? "... " : "") + body.slice(start, end) + (end < body.length ? " ..." : "");
  }

  function runSearch(index, query) {
    var q = text(query).trim();
    if (q.length < 2) {
      return [];
    }

    return index
      .map(function (entry) {
        var title = text(entry.title);
        var location = text(entry.location);
        var body = text(entry.text || entry.content);
        var score = 0;
        if (title.indexOf(q) >= 0) score += 6;
        if (location.indexOf(q) >= 0) score += 3;
        if (body.indexOf(q) >= 0) score += 1;
        return { entry: entry, score: score };
      })
      .filter(function (result) { return result.score > 0; })
      .sort(function (a, b) { return b.score - a.score; })
      .slice(0, 8);
  }

  function renderResults(container, results, query, baseUrl) {
    container.innerHTML = "";
    if (!query || query.trim().length < 2) {
      return;
    }

    if (!results.length) {
      var empty = document.createElement("div");
      empty.className = "search-empty";
      empty.textContent = "No matching documents.";
      container.appendChild(empty);
      return;
    }

    results.forEach(function (result) {
      var entry = result.entry;
      var link = document.createElement("a");
      link.className = "search-result";
      link.href = resolveUrl(baseUrl, entry.location || "");

      var title = document.createElement("strong");
      title.textContent = entry.title || entry.location || "Untitled";
      link.appendChild(title);

      var summary = document.createElement("span");
      summary.textContent = excerpt(entry, query);
      link.appendChild(summary);

      container.appendChild(link);
    });
  }

  function initSearch() {
    var config = window.superbicheSearch || {};
    if (!config.enabled) return;

    var input = document.getElementById("mkdocs-search-query");
    var results = document.getElementById("mkdocs-search-results");
    if (!input || !results || !window.fetch) return;

    fetch(resolveUrl(config.baseUrl, "search/search_index.json"))
      .then(function (response) { return response.json(); })
      .then(function (data) {
        var docs = data.docs || [];
        input.addEventListener("input", function () {
          renderResults(results, runSearch(docs, input.value), input.value, config.baseUrl);
        });
      })
      .catch(function () {
        results.innerHTML = '<div class="search-empty">Search index unavailable.</div>';
      });
  }

  function absoluteDocsRoot(baseUrl) {
    var expanded = window.location.pathname.split("/");
    expanded.pop();
    var isSubdir = false;

    (baseUrl || ".").split("/").forEach(function (bit, i) {
      if (bit === "" && i === 0) {
        isSubdir = false;
        expanded = [""];
      } else if (bit === "." || bit === "") {
        isSubdir = true;
      } else if (bit === "..") {
        if (expanded.length > 1) {
          isSubdir = true;
          expanded.pop();
        }
      } else {
        isSubdir = false;
        expanded.push(bit);
      }
    });

    if (isSubdir) expanded.push("");
    return expanded.join("/").replace(/\/?$/, "/");
  }

  function currentVersionSlug(rootPath) {
    var bits = rootPath.split("/").filter(Boolean);
    return bits.length ? bits[bits.length - 1] : "";
  }

  function currentPagePath(rootPath) {
    var current = window.location.pathname;
    if (current.indexOf(rootPath) !== 0) {
      return "";
    }
    return current.slice(rootPath.length);
  }

  function versionIsHidden(version, realVersion) {
    return version.version !== realVersion &&
      version.properties &&
      version.properties.hidden;
  }

  function initVersions() {
    var config = window.superbicheVersions || {};
    if (!config.enabled || !window.fetch) return;

    var rootPath = absoluteDocsRoot(config.baseUrl);
    var slug = currentVersionSlug(rootPath);
    if (!slug) return;

    fetch(rootPath + "../versions.json")
      .then(function (response) {
        if (!response.ok) throw new Error("versions unavailable");
        return response.json();
      })
      .then(function (versions) {
        if (!Array.isArray(versions) || versions.length === 0) return;

        var current = versions.find(function (item) {
          return item.version === slug || (item.aliases || []).indexOf(slug) >= 0;
        });
        if (!current) return;

        var panel = document.createElement("div");
        panel.className = "version-panel";

        var label = document.createElement("label");
        label.className = "version-panel__label";
        label.htmlFor = "superbiche-version-select";
        label.textContent = "Version";
        panel.appendChild(label);

        var select = document.createElement("select");
        select.id = "superbiche-version-select";
        select.className = "version-panel__select";

        versions
          .filter(function (item) { return !versionIsHidden(item, current.version); })
          .forEach(function (item) {
            var option = new Option(item.title || item.version, item.version, false, item.version === current.version);
            select.add(option);
          });

        select.addEventListener("change", function () {
          var pagePath = currentPagePath(rootPath);
          window.location.href = rootPath + "../" + this.value + "/" + pagePath;
        });

        panel.appendChild(select);

        var sidebar = document.querySelector(".sidebar");
        if (sidebar) {
          sidebar.insertBefore(panel, sidebar.firstChild);
        }
      })
      .catch(function () {
        return;
      });
  }

  initSearch();
  initVersions();
})();
