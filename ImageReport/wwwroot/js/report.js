const reportStatus = document.querySelector("#report-status");
const reportErrors = document.querySelector("#report-errors");
const imageRows = document.querySelector("#image-cards");
const signOutButton = document.querySelector("#sign-out");
const refreshButton = document.querySelector("#refresh-report");
const updatedAt = document.querySelector("#report-updated");
const summaryServices = document.querySelector("#summary-services");
const summarySwarms = document.querySelector("#summary-swarms");
const summaryScanned = document.querySelector("#summary-scanned");
const summaryTotal = document.querySelector("#summary-total");
const summaryUnknown = document.querySelector("#summary-unknown");
const summaryTotalVulnerabilities = document.querySelector("#summary-vulns");
const summaryBar = document.querySelector("#summary-bar");
const reportRowCount = document.querySelector("#report-row-count");
const searchInput = document.querySelector("#filter-search");
const swarmFilter = document.querySelector("#filter-swarm");
const scanFilter = document.querySelector("#filter-scan");
const clearFiltersButton = document.querySelector("#clear-filters");
const severities = ["critical", "high", "medium", "low", "none"];
const severityLabels = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  none: "Negligible"
};

let allImages = [];
let sortField = "critical";
let sortDirection = -1;
let nextDigestDetailsId = 0;

function createTextElement(tagName, className, text) {
  const element = document.createElement(tagName);
  element.className = className;
  element.textContent = text;
  return element;
}

function createCopyButton(value, label) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy-image-button";
  button.dataset.copyValue = value;
  button.dataset.copyLabel = label;
  button.setAttribute("aria-label", `Copy ${label}`);
  button.title = `Copy ${label}`;
  button.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="7" y="6" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M13 6V4.5A1.5 1.5 0 0 0 11.5 3h-7A1.5 1.5 0 0 0 3 4.5v9A1.5 1.5 0 0 0 4.5 15H7" stroke="currentColor" stroke-width="1.5"/></svg>';
  return button;
}

function createImageIdentifier(label, value, copyLabel) {
  const identifier = document.createElement("div");
  identifier.className = "image-identifier";
  identifier.title = value ?? `${label} unavailable`;
  identifier.append(
    createTextElement("span", "image-identifier-label", label),
    createTextElement("code", "image-identifier-value", value ?? "Unavailable")
  );

  if (value) {
    identifier.append(createCopyButton(value, copyLabel));
  }

  return identifier;
}

function positionDigestDetails(trigger, details) {
  const triggerBounds = trigger.getBoundingClientRect();
  const detailsBounds = details.getBoundingClientRect();
  const left = Math.max(
    12,
    Math.min(triggerBounds.left, window.innerWidth - detailsBounds.width - 12)
  );
  const top = triggerBounds.bottom + detailsBounds.height + 12 <= window.innerHeight
    ? triggerBounds.bottom + 6
    : Math.max(12, triggerBounds.top - detailsBounds.height - 6);

  details.style.left = `${left}px`;
  details.style.top = `${top}px`;
}

function connectDigestDetails(trigger, details, imageReference) {
  let closeTimer;
  const targets = [trigger, imageReference];

  const show = event => {
    window.clearTimeout(closeTimer);
    if (!details.matches(":popover-open")) {
      details.showPopover();
    }
    for (const target of targets) {
      target.setAttribute("aria-expanded", "true");
    }
    positionDigestDetails(event.currentTarget, details);
  };

  const scheduleClose = () => {
    window.clearTimeout(closeTimer);
    closeTimer = window.setTimeout(() => {
      const pointerIsInside = targets.some(target => target.matches(":hover"));
      const focusIsInside = targets.includes(document.activeElement)
        || details.contains(document.activeElement);
      if (!pointerIsInside && !details.matches(":hover") && !focusIsInside) {
        details.hidePopover();
        for (const target of targets) {
          target.setAttribute("aria-expanded", "false");
        }
      }
    }, 140);
  };

  details.addEventListener("toggle", () => {
    for (const target of targets) {
      target.setAttribute("aria-expanded", String(details.matches(":popover-open")));
    }
  });
  for (const target of targets) {
    target.addEventListener("pointerenter", show);
    target.addEventListener("pointerleave", scheduleClose);
    target.addEventListener("focus", show);
    target.addEventListener("blur", scheduleClose);
  }
  details.addEventListener("pointerenter", () => window.clearTimeout(closeTimer));
  details.addEventListener("pointerleave", scheduleClose);
  details.addEventListener("focusout", scheduleClose);
}

function createDigestComparison(image, imageReference) {
  const matches = Boolean(
    image.digest
    && image.localRepoDigest
    && image.digest === image.localRepoDigest
  );
  const status = matches ? "match" : "mismatch";
  const label = matches ? "Harbor and local digests match" : "Harbor and local digests do not match";
  const container = document.createElement("div");
  container.className = "digest-comparison";

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = `digest-comparison-status is-${status}`;
  trigger.setAttribute("aria-label", `${label}. Hover or focus to view digest details.`);
  trigger.setAttribute("aria-haspopup", "dialog");
  trigger.setAttribute("aria-expanded", "false");
  trigger.innerHTML = matches
    ? '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="currentColor"/><path d="m6 10 2.5 2.5L14 7" stroke="white" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    : '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="currentColor"/><path d="m7 7 6 6m0-6-6 6" stroke="white" stroke-width="1.7" stroke-linecap="round"/></svg>';

  const details = document.createElement("div");
  details.id = `digest-details-${nextDigestDetailsId++}`;
  details.className = "digest-details";
  details.setAttribute("popover", "manual");
  details.setAttribute("role", "dialog");
  details.setAttribute("aria-label", "Image digest details");
  details.append(
    createTextElement("strong", `digest-details-status is-${status}`, label),
    createImageIdentifier(
      "Image reference",
      image.image ?? image.repository ?? "Image reference unavailable",
      "image reference"
    ),
    createImageIdentifier("Harbor digest", image.digest, "Harbor digest"),
    createImageIdentifier("Local repo digest", image.localRepoDigest, "local repository digest"),
    createImageIdentifier("Local image ID", image.localImageId, "local image ID")
  );

  trigger.setAttribute("aria-controls", details.id);
  imageReference.tabIndex = 0;
  imageReference.setAttribute("aria-label", "Image reference. Hover or focus to view image and digest details.");
  imageReference.setAttribute("aria-controls", details.id);
  imageReference.setAttribute("aria-haspopup", "dialog");
  imageReference.setAttribute("aria-expanded", "false");
  container.append(trigger, details);
  connectDigestDetails(trigger, details, imageReference);
  return container;
}

function getCount(image, severity) {
  const count = image.vulnerabilities?.count?.[severity];
  return Number.isInteger(count) && count >= 0 ? count : null;
}

function createDistributionBar(image) {
  const bar = document.createElement("div");
  bar.className = "severity-bar";
  bar.setAttribute("role", "img");
  bar.tabIndex = 0;

  const counts = severities.map(severity => getCount(image, severity));
  const isScanned = image.vulnerabilities?.status === "complete";
  const hasCompleteCounts = counts.every(count => count !== null);

  if (!isScanned || !hasCompleteCounts) {
    bar.classList.add("is-empty");
    bar.setAttribute("aria-label", "Vulnerability distribution unavailable");
    bar.title = "Vulnerability distribution unavailable";
    return bar;
  }

  const total = counts.reduce((sum, count) => sum + count, 0);
  const distribution = severities
    .map((severity, index) => `${severityLabels[severity]}: ${counts[index]}`)
    .join(" · ");
  bar.setAttribute(
    "aria-label",
    total === 0 ? "No vulnerabilities found" : distribution
  );
  bar.title = total === 0 ? "No vulnerabilities found" : distribution;

  if (total === 0) {
    bar.classList.add("is-empty");
    return bar;
  }

  for (const [index, count] of counts.entries()) {
    if (count === 0) {
      continue;
    }

    const segment = document.createElement("span");
    segment.className = `severity-segment is-${severities[index]}`;
    segment.style.flex = `${count} 1 0`;
    bar.append(segment);
  }

  return bar;
}

function createSeverityCount(image, severity) {
  const button = document.createElement("button");
  button.type = "button";
  const count = getCount(image, severity);
  button.className = `severity-count is-${severity}${count === null ? " is-unavailable" : ""}`;
  button.dataset.sort = severity;
  const countElement = createTextElement("strong", "severity-count-value", count === null ? "-" : String(count));

  button.setAttribute("aria-label", `Sort by ${severityLabels[severity]}`);
  button.append(
    createTextElement("span", "severity-count-label", severityLabels[severity]),
    countElement,
    createTextElement("span", "severity-sort-indicator", "")
  );
  return button;
}

function createImageRow(image) {
  const row = document.createElement("tr");
  row.className = "image-row";

  const serviceCell = document.createElement("td");
  serviceCell.className = "col-service-cell";
  serviceCell.append(createTextElement("span", "service-name", image.service ?? "Unnamed service"));
  serviceCell.append(createTextElement("span", "service-swarm", image.swarm ?? "Unknown Swarm"));

  const imageCell = document.createElement("td");
  imageCell.className = "col-image-cell";
  const imageReferenceText = image.image ?? image.repository ?? "Image reference unavailable";
  const imageReferenceRow = document.createElement("div");
  imageReferenceRow.className = "image-reference-row";

  const imageReference = createTextElement("code", "image-reference", imageReferenceText);
  imageReferenceRow.append(createDigestComparison(image, imageReference));
  imageReferenceRow.append(imageReference);

  const copyButton = createCopyButton(imageReferenceText, "image reference");
  imageReferenceRow.append(copyButton);
  imageCell.append(imageReferenceRow);

  const isScanned = image.vulnerabilities?.status === "complete";
  const scanCell = document.createElement("td");
  scanCell.className = "col-scan-cell";
  scanCell.append(createTextElement(
    "span",
    `scan-status ${isScanned ? "is-available" : "is-unknown"}`,
    isScanned ? "Scanned" : "Unknown"
  ));

  const distributionCell = document.createElement("td");
  distributionCell.className = "col-bar-cell";
  if (isScanned) {
    distributionCell.append(createDistributionBar(image));

    const severityCounts = document.createElement("div");
    severityCounts.className = "severity-counts";
    for (const severity of severities) {
      severityCounts.append(createSeverityCount(image, severity));
    }
    distributionCell.append(severityCounts);
  }

  row.append(serviceCell, imageCell, scanCell, distributionCell);

  return row;
}

function updateSwarmOptions(images) {
  const selectedSwarm = swarmFilter.value;
  const swarms = [...new Set(images.map(image => image.swarm).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right));

  swarmFilter.replaceChildren(new Option("All Swarms", ""));

  for (const swarm of swarms) {
    swarmFilter.add(new Option(swarm, swarm));
  }

  if (swarms.includes(selectedSwarm)) {
    swarmFilter.value = selectedSwarm;
  }
}

function matchesFilters(image) {
  const searchTerm = searchInput.value.trim().toLocaleLowerCase();
  const searchableText = [image.swarm, image.service, image.image]
    .filter(Boolean)
    .join(" ")
    .toLocaleLowerCase();
  const matchesSearch = searchTerm === "" || searchableText.includes(searchTerm);
  const matchesSwarm = swarmFilter.value === "" || image.swarm === swarmFilter.value;
  const scanStatus = image.vulnerabilities?.status === "complete" ? "complete" : "unknown";
  const matchesScan = scanFilter.value === "" || scanStatus === scanFilter.value;

  return matchesSearch && matchesSwarm && matchesScan;
}

function compareImages(left, right) {
  const leftCount = getCount(left, sortField);
  const rightCount = getCount(right, sortField);

  if (leftCount === null && rightCount !== null) {
    return 1;
  }

  if (rightCount === null && leftCount !== null) {
    return -1;
  }

  if (leftCount !== rightCount) {
    return ((leftCount ?? 0) - (rightCount ?? 0)) * sortDirection;
  }

  return (left.service ?? "").localeCompare(right.service ?? "");
}

function updateSortHeaders() {
  for (const button of document.querySelectorAll(".severity-count")) {
    const isActive = button.dataset.sort === sortField;
    const label = severityLabels[button.dataset.sort];
    const indicator = button.querySelector(".severity-sort-indicator");

    button.setAttribute("aria-pressed", String(isActive));
    button.setAttribute(
      "aria-label",
      isActive
        ? `Sort by ${label}, currently ${sortDirection === -1 ? "descending" : "ascending"}`
        : `Sort by ${label}`
    );
    indicator.textContent = isActive ? (sortDirection === -1 ? "↓" : "↑") : "";
  }
}

function renderImages() {
  const filteredImages = allImages.filter(matchesFilters).sort(compareImages);
  imageRows.replaceChildren();

  if (filteredImages.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "image-list-empty";
    cell.colSpan = 4;
    cell.append(createTextElement(
      "strong",
      "image-list-empty-title",
      allImages.length === 0 ? "No deployed services found" : "No services match"
    ));
    cell.append(createTextElement(
      "span",
      "image-list-empty-description",
      allImages.length === 0
        ? "There are no Swarm services to display."
        : "Try a different search or clear the filters."
    ));
    row.append(cell);
    imageRows.append(row);
  } else {
    for (const image of filteredImages) {
      imageRows.append(createImageRow(image));
    }
  }

  reportRowCount.textContent = `Showing ${filteredImages.length} of ${allImages.length} services`;
  clearFiltersButton.hidden = !searchInput.value && !swarmFilter.value && !scanFilter.value;
  updateSortHeaders();
}

function updateSummary(images) {
  const scannedImages = images.filter(image => image.vulnerabilities?.status === "complete");
  const unknownCount = images.length - scannedImages.length;
  const swarmCount = new Set(images.map(image => image.swarm).filter(Boolean)).size;
  const totals = Object.fromEntries(severities.map(severity => {
    const counts = scannedImages.map(image => getCount(image, severity));
    const total = counts.length === 0 || counts.some(count => count === null)
      ? null
      : counts.reduce((sum, count) => sum + count, 0);

    return [severity, total];
  }));
  const totalVulnerabilities = severities.every(severity => totals[severity] !== null)
    ? severities.reduce((sum, severity) => sum + totals[severity], 0)
    : null;

  summaryServices.textContent = String(images.length);
  summarySwarms.textContent = String(swarmCount);
  summaryScanned.textContent = String(scannedImages.length);
  summaryTotal.textContent = String(images.length);
  summaryUnknown.textContent = String(unknownCount);
  summaryTotalVulnerabilities.textContent = totalVulnerabilities === null
    ? "-"
    : String(totalVulnerabilities);

  for (const severity of severities) {
    document.querySelector(`#summary-${severity === "none" ? "negligible" : severity}`).textContent =
      totals[severity] === null ? "-" : String(totals[severity]);
  }

  summaryBar.replaceChildren();
  const hasCompleteTotals = severities.every(severity => totals[severity] !== null);
  const summaryCounts = severities.map(severity => totals[severity]);
  const summaryTotalCount = hasCompleteTotals
    ? summaryCounts.reduce((sum, count) => sum + count, 0)
    : null;

  summaryBar.classList.toggle("is-empty", summaryTotalCount === null || summaryTotalCount === 0);
  summaryBar.setAttribute(
    "aria-label",
    summaryTotalCount === null
      ? "Vulnerability distribution unavailable"
      : `${summaryTotalCount} vulnerabilities across scanned services`
  );

  if (summaryTotalCount > 0) {
    for (const [index, count] of summaryCounts.entries()) {
      if (count === 0) {
        continue;
      }

      const segment = document.createElement("span");
      segment.className = `severity-segment is-${severities[index]}`;
      segment.style.flex = `${count} 1 0`;
      summaryBar.append(segment);
    }
  }
}

function renderErrors(errors) {
  reportErrors.replaceChildren();

  for (const error of errors) {
    const message = document.createElement("p");
    message.textContent = `${error.swarm}: ${error.message}`;
    reportErrors.append(message);
  }
}

function clearFilters() {
  searchInput.value = "";
  swarmFilter.value = "";
  scanFilter.value = "";
  renderImages();
}

async function loadReport() {
  refreshButton.disabled = true;
  refreshButton.classList.add("is-loading");
  reportStatus.dataset.state = "loading";
  reportStatus.textContent = "Loading services…";
  reportErrors.replaceChildren();

  try {
    const response = await fetch("/api/images", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });

    if (response.status === 401) {
      window.location.replace("/login.html");
      return;
    }

    if (response.status === 403) {
      reportStatus.dataset.state = "error";
      reportStatus.textContent = "Your account does not have access to this report.";
      return;
    }

    if (!response.ok) {
      throw new Error("Could not load the image report.");
    }

    const report = await response.json();
    allImages = Array.isArray(report.images) ? report.images : [];
    const errors = Array.isArray(report.errors) ? report.errors : [];

    updateSwarmOptions(allImages);
    updateSummary(allImages);
    renderImages();
    renderErrors(errors);
    reportStatus.dataset.state = errors.length > 0 ? "error" : "success";
    reportStatus.textContent = errors.length > 0
      ? `${errors.length} source${errors.length === 1 ? "" : "s"} could not be collected`
      : `${allImages.length} service${allImages.length === 1 ? "" : "s"}`;
    updatedAt.textContent = `Updated ${new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit"
    }).format(new Date())}`;
  } catch {
    reportStatus.dataset.state = "error";
    reportStatus.textContent = "Could not load the image report. Please try again.";
  } finally {
    refreshButton.disabled = false;
    refreshButton.classList.remove("is-loading");
  }
}

searchInput.addEventListener("input", renderImages);
swarmFilter.addEventListener("change", renderImages);
scanFilter.addEventListener("change", renderImages);
clearFiltersButton.addEventListener("click", clearFilters);
refreshButton.addEventListener("click", loadReport);

imageRows.addEventListener("click", async event => {
  const copyButton = event.target.closest(".copy-image-button");
  if (copyButton) {
    const label = copyButton.dataset.copyLabel;

    try {
      await navigator.clipboard.writeText(copyButton.dataset.copyValue);
      copyButton.classList.add("is-copied");
      copyButton.setAttribute("aria-label", `${label} copied`);
      copyButton.title = `${label} copied`;
      copyButton.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m4 10 4 4 8-8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

      window.setTimeout(() => {
        if (!copyButton.isConnected) {
          return;
        }

        copyButton.classList.remove("is-copied");
        copyButton.setAttribute("aria-label", `Copy ${label}`);
        copyButton.title = `Copy ${label}`;
        copyButton.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="7" y="6" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M13 6V4.5A1.5 1.5 0 0 0 11.5 3h-7A1.5 1.5 0 0 0 3 4.5v9A1.5 1.5 0 0 0 4.5 15H7" stroke="currentColor" stroke-width="1.5"/></svg>';
      }, 1800);
    } catch {
      reportStatus.dataset.state = "error";
      reportStatus.textContent = "Could not copy image reference. Check clipboard permissions and try again.";
    }

    return;
  }

  const button = event.target.closest(".severity-count");
  if (!button || !severities.includes(button.dataset.sort)) {
    return;
  }

  if (sortField === button.dataset.sort) {
    sortDirection *= -1;
  } else {
    sortField = button.dataset.sort;
    sortDirection = -1;
  }

  renderImages();
});

signOutButton.addEventListener("click", async () => {
  signOutButton.disabled = true;

  try {
    const response = await fetch("/auth/logout", {
      method: "POST",
      credentials: "same-origin"
    });

    if (!response.ok) {
      reportStatus.dataset.state = "error";
      reportStatus.textContent = "Could not sign out. Please try again.";
      return;
    }

    window.location.replace("/login.html");
  } catch {
    reportStatus.dataset.state = "error";
    reportStatus.textContent = "Could not reach the report service. Please try again.";
  } finally {
    signOutButton.disabled = false;
  }
});

loadReport();
