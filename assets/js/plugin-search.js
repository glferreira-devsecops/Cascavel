/* CASCAVEL — Plugin tables search & category filter (CSP-strict safe, no inline) */
(function () {
  "use strict";

  function init() {
    var section = document.getElementById("plugins");
    if (!section) return;

    var blocks = Array.prototype.slice.call(
      section.querySelectorAll(".plugin-category-block")
    );
    if (!blocks.length) return;

    var isEn =
      (document.documentElement.lang || "pt").toLowerCase().indexOf("en") === 0;
    var i18n = isEn
      ? {
          placeholder: "Search plugins, files or techniques…",
          all: "All categories",
          none: "No plugins match your search.",
          count: function (n) {
            return n + (n === 1 ? " plugin" : " plugins");
          }
        }
      : {
          placeholder: "Buscar plugins, arquivos ou técnicas…",
          all: "Todas as categorias",
          none: "Nenhum plugin corresponde à sua busca.",
          count: function (n) {
            return n + (n === 1 ? " plugin" : " plugins");
          }
        };

    // Index each category block and its rows once.
    var catalog = blocks.map(function (block) {
      var heading = block.querySelector("h3");
      var name = heading ? heading.textContent.replace(/\s+/g, " ").trim() : "";
      var rows = Array.prototype.slice.call(block.querySelectorAll("tbody tr"));
      var indexed = rows.map(function (tr) {
        return { tr: tr, text: tr.textContent.toLowerCase() };
      });
      return { block: block, name: name, rows: indexed };
    });

    // Build controls.
    var controls = document.createElement("div");
    controls.className = "plugin-search-controls";

    var input = document.createElement("input");
    input.type = "search";
    input.className = "plugin-search-input";
    input.setAttribute("aria-label", i18n.placeholder);
    input.placeholder = i18n.placeholder;

    var select = document.createElement("select");
    select.className = "plugin-search-filter";
    select.setAttribute("aria-label", i18n.all);

    var optAll = document.createElement("option");
    optAll.value = "__all__";
    optAll.textContent = i18n.all;
    select.appendChild(optAll);

    catalog.forEach(function (cat, idx) {
      var opt = document.createElement("option");
      opt.value = String(idx);
      opt.textContent = cat.name;
      select.appendChild(opt);
    });

    var counter = document.createElement("span");
    counter.className = "plugin-search-count";

    controls.appendChild(input);
    controls.appendChild(select);
    controls.appendChild(counter);

    var empty = document.createElement("p");
    empty.className = "plugin-search-empty";
    empty.textContent = i18n.none;
    empty.style.display = "none";

    var container =
      section.querySelector(".plugin-categories-detailed") ||
      (blocks[0] && blocks[0].parentNode);
    if (container && container.parentNode) {
      container.parentNode.insertBefore(controls, container);
      container.parentNode.insertBefore(empty, container.nextSibling);
    }

    function apply() {
      var q = input.value.toLowerCase().trim();
      var catSel = select.value;
      var total = 0;

      catalog.forEach(function (cat, idx) {
        var catVisible = catSel === "__all__" || catSel === String(idx);
        var shown = 0;

        cat.rows.forEach(function (row) {
          var match = catVisible && (q === "" || row.text.indexOf(q) !== -1);
          row.tr.style.display = match ? "" : "none";
          if (match) shown++;
        });

        cat.block.style.display = catVisible && shown > 0 ? "" : "none";
        total += shown;
      });

      counter.textContent = i18n.count(total);
      empty.style.display = total === 0 ? "" : "none";
    }

    input.addEventListener("input", apply);
    select.addEventListener("change", apply);
    apply();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
