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
const summaryScanBreakdown = document.querySelector("#summary-scan-breakdown");
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
const scanStatusLabels = {
  complete: "Scanned",
  imageNotInHarbor: "Registry not matched",
  harborUnavailable: "Harbor unavailable",
  harborAuthenticationFailed: "Harbor authentication failed",
  harborAccessDenied: "Harbor access denied",
  harborServerError: "Harbor server error",
  harborRequestRejected: "Harbor rejected request",
  harborTimeout: "Harbor timed out",
  harborConnectionFailed: "Harbor connection failed",
  harborResponseReadFailed: "Harbor response unreadable",
  invalidScanReport: "Invalid scan report",
  digestUnavailable: "Digest unavailable",
  scanNotFound: "Harbor returned 404 for scan",
  harborNotConfigured: "Harbor not configured",
  unknown: "Reason unavailable"
};
const scanStatusDescriptions = {
  complete: "A Harbor vulnerability report is available.",
  imageNotInHarbor: "The image registry does not match the configured Harbor address.",
  harborUnavailable: "Harbor could not provide vulnerability scan data.",
  harborAuthenticationFailed: "Harbor rejected the configured credentials.",
  harborAccessDenied: "The configured Harbor account does not have permission to read this report.",
  harborServerError: "Harbor returned a server error.",
  harborRequestRejected: "Harbor rejected the vulnerability report request.",
  harborTimeout: "Harbor did not respond before the request timed out.",
  harborConnectionFailed: "The report service could not connect to Harbor.",
  harborResponseReadFailed: "The report service could not read Harbor's response.",
  invalidScanReport: "Harbor returned a response that was not a valid vulnerability report.",
  digestUnavailable: "A digest was not available for the Harbor lookup.",
  scanNotFound: "Harbor returned HTTP 404 for the vulnerability report lookup. This does not prove the artifact or scan is absent; access may be restricted.",
  harborNotConfigured: "Harbor vulnerability lookup is not configured.",
  unknown: "The scan result did not include a reason."
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
  const registryMatched = image.harborRegistryMatched;
  const imageUpdate = image.imageUpdate ?? {};
  const updateStatus = ["upToDate", "updateAvailable"].includes(imageUpdate.status)
    ? imageUpdate.status
    : "unknown";
  const updateLabel = updateStatus === "upToDate"
    ? "Up to date for configured tag"
    : updateStatus === "updateAvailable"
      ? "Update available for configured tag"
      : getUpdateUnknownLabel(imageUpdate.reason);
  const updateDescription = imageUpdate.detail
    ? `${updateLabel}. ${imageUpdate.detail}`
    : updateLabel;
  const digestMatches = Boolean(
    image.digest
    && image.localRepoDigest
    && image.digest === image.localRepoDigest
  );
  const container = document.createElement("div");
  container.className = "digest-comparison";

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = `image-update-status is-${updateStatus}`;
  trigger.setAttribute("aria-label", `${updateDescription}. Hover or focus to view image details.`);
  trigger.setAttribute("aria-haspopup", "dialog");
  trigger.setAttribute("aria-expanded", "false");
  trigger.title = updateDescription;
  trigger.innerHTML = updateStatus === "upToDate"
    ? '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="m4 10 4 4 8-8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    : updateStatus === "updateAvailable"
      ? '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 15V4m0 0L5.5 8.5M10 4l4.5 4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17h12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
      : '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7.5" stroke="currentColor" stroke-width="1.5"/><path d="M10 9v5m0-8h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';

  const registryIndicator = image.localImageId && registryMatched === false
    ? createRegistryMismatchIndicator()
    : null;
  const details = document.createElement("div");
  details.id = `digest-details-${nextDigestDetailsId++}`;
  details.className = "digest-details";
  details.setAttribute("popover", "manual");
  details.setAttribute("role", "dialog");
  details.setAttribute("aria-label", "Image update and digest details");
  details.append(
    createTextElement("strong", `digest-details-status is-${updateStatus}`, updateDescription),
    createImageIdentifier(
      "Image reference",
      image.image ?? image.repository ?? "Image reference unavailable",
      "image reference"
    )
  );

  details.append(createImageIdentifier(
    "Deployed image digest",
    image.digest,
    "deployed image digest"
  ));

  const localDigestLabel = digestMatches
    ? "Local repo digest (matches image ref)"
    : "Local repo digest";
  details.append(createImageIdentifier(localDigestLabel, image.localRepoDigest, "local repository digest"));

  details.append(createImageIdentifier(
    "Harbor tag digest",
    imageUpdate.currentDigest,
    "Harbor tag digest"
  ));

  if (image.localImageId) {
    details.append(createImageIdentifier("Local image ID", image.localImageId, "local image ID"));
  }

  trigger.setAttribute("aria-controls", details.id);
  imageReference.tabIndex = 0;
  imageReference.setAttribute("aria-label", "Image reference. Hover or focus to view image and digest details.");
  imageReference.setAttribute("aria-controls", details.id);
  imageReference.setAttribute("aria-haspopup", "dialog");
  imageReference.setAttribute("aria-expanded", "false");
  if (registryIndicator) {
    container.append(registryIndicator);
  }
  container.append(trigger, details);
  connectDigestDetails(trigger, details, imageReference);
  return container;
}

function createRegistryMismatchIndicator() {
  const indicator = document.createElement("span");
  indicator.className = "harbor-registry-mismatch";
  const label = "Local image is not from the configured Harbor registry.";
  indicator.setAttribute("role", "img");
  indicator.setAttribute("aria-label", label);
  indicator.title = label;
  indicator.innerHTML = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 21h10M9 21l1.5-11h3L15 21M10.5 10 8 6h8l-2.5 4M8 6 5 4m11 2 3-2M12 3V1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="m5 5 14 14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
  return indicator;
}

function getUpdateUnknownLabel(reason) {
  const labels = {
    tagUnavailable: "Update status unknown: image has no explicit tag",
    tagLookupNotFound: "Update status unknown: Harbor returned 404 for tag lookup",
    tagNotFound: "Update status unknown: Harbor returned 404 for tag lookup",
    tagLookupUnavailable: "Update status unknown: Harbor tag lookup was unavailable",
    digestUnavailable: "Update status unknown: deployed digest unavailable",
    harborNotConfigured: "Update status unknown: Harbor not configured",
    harborAuthenticationFailed: "Update status unknown: Harbor authentication failed",
    harborAccessDenied: "Update status unknown: Harbor access denied",
    harborServerError: "Update status unknown: Harbor server error",
    harborRequestRejected: "Update status unknown: Harbor rejected the request",
    harborTimeout: "Update status unknown: Harbor timed out",
    harborConnectionFailed: "Update status unknown: Harbor connection failed",
    harborResponseReadFailed: "Update status unknown: Harbor response unreadable",
    invalidArtifactResponse: "Update status unknown: invalid Harbor artifact response",
    imageNotInHarbor: "Update status unknown: registry not matched"
  };
  return labels[reason] ?? "Update status unknown";
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

  const scanStatus = getScanStatus(image);
  const isScanned = scanStatus === "complete";
  const scanCell = document.createElement("td");
  scanCell.className = "col-scan-cell";
  const statusElement = createTextElement(
    "span",
    `scan-status ${isScanned ? "is-available" : "is-unknown"}`,
    scanStatusLabels[scanStatus]
  );
  statusElement.title = image.vulnerabilities?.detail
    ? `${scanStatusDescriptions[scanStatus]} ${image.vulnerabilities.detail}`
    : scanStatusDescriptions[scanStatus];
  if (scanStatus === "harborServerError" || scanStatus === "harborRequestRejected") {
    const httpStatus = image.vulnerabilities?.detail?.match(/^HTTP (\d{3})/)?.[1];
    if (httpStatus) {
      statusElement.textContent = `Harbor HTTP ${httpStatus}`;
    }
  }
  scanCell.append(statusElement);

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

function getScanStatus(image) {
  if (image.vulnerabilities?.status === "complete") {
    return "complete";
  }

  const reason = image.vulnerabilities?.reason;
  return Object.hasOwn(scanStatusLabels, reason) ? reason : "unknown";
}

function matchesFilters(image) {
  const searchTerm = searchInput.value.trim().toLocaleLowerCase();
  const searchableText = [image.swarm, image.service, image.image]
    .filter(Boolean)
    .join(" ")
    .toLocaleLowerCase();
  const matchesSearch = searchTerm === "" || searchableText.includes(searchTerm);
  const matchesSwarm = swarmFilter.value === "" || image.swarm === swarmFilter.value;
  const scanStatus = getScanStatus(image);
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
  const scanStatusCounts = new Map();
  for (const image of images) {
    const scanStatus = getScanStatus(image);
    scanStatusCounts.set(scanStatus, (scanStatusCounts.get(scanStatus) ?? 0) + 1);
  }
  const missingScanCount = images.length - scannedImages.length;
  const scanBreakdown = Object.entries(scanStatusLabels)
    .filter(([status]) => status !== "complete")
    .map(([status, label]) => ({
      label,
      count: scanStatusCounts.get(status) ?? 0
    }))
    .filter(item => item.count > 0)
    .map(item => `${item.count} ${item.label}`)
    .join(", ");
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
  summaryScanBreakdown.textContent = missingScanCount === 0
    ? "All services have scan results"
    : `${missingScanCount} without scan results: ${scanBreakdown}`;
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
    const item = document.createElement("div");
    item.className = "source-error-item";
    item.append(
      createTextElement("strong", "source-error-name", error.swarm),
      createTextElement("span", "source-error-message", error.message)
    );
    reportErrors.append(item);
  }
}

function connectSourceErrorDetails(trigger, details) {
  let closeTimer;

  const show = () => {
    window.clearTimeout(closeTimer);
    if (!details.matches(":popover-open")) {
      details.showPopover();
    }
    trigger.setAttribute("aria-expanded", "true");
    positionDigestDetails(trigger, details);
  };

  const scheduleClose = () => {
    window.clearTimeout(closeTimer);
    closeTimer = window.setTimeout(() => {
      const focusIsInside = trigger === document.activeElement
        || details.contains(document.activeElement);
      if (!trigger.matches(":hover") && !details.matches(":hover") && !focusIsInside) {
        details.hidePopover();
        trigger.setAttribute("aria-expanded", "false");
      }
    }, 140);
  };

  trigger.addEventListener("pointerenter", show);
  trigger.addEventListener("pointerleave", scheduleClose);
  trigger.addEventListener("focus", show);
  trigger.addEventListener("blur", scheduleClose);
  details.addEventListener("pointerenter", () => window.clearTimeout(closeTimer));
  details.addEventListener("pointerleave", scheduleClose);
  details.addEventListener("focusout", scheduleClose);
  details.addEventListener("toggle", () => {
    trigger.setAttribute("aria-expanded", String(details.matches(":popover-open")));
  });
}

function renderReportStatus(message, errors = []) {
  reportStatus.replaceChildren(document.createTextNode(message));

  if (errors.length === 0) {
    return;
  }

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "source-error-trigger";
  trigger.setAttribute("aria-label", "View source collection errors");
  trigger.setAttribute("aria-haspopup", "dialog");
  trigger.setAttribute("aria-expanded", "false");
  trigger.setAttribute("aria-controls", "report-errors");
  trigger.title = "View source collection errors";
  trigger.innerHTML = '<svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="1.5"/><path d="M10 9v5m0-8h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';

  reportErrors.setAttribute("popover", "manual");
  reportErrors.setAttribute("role", "dialog");
  reportErrors.setAttribute("aria-label", "Source collection errors");
  connectSourceErrorDetails(trigger, reportErrors);
  reportStatus.append(trigger);
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
  renderReportStatus("Loading services…");
  reportErrors.replaceChildren();
  reportErrors.hidePopover();

  try {
    const response = await fetch("api/images", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });

    if (response.status === 401) {
      window.location.replace("login.html");
      return;
    }

    if (response.status === 403) {
      reportStatus.dataset.state = "error";
      renderReportStatus("Your account does not have access to this report.");
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
    renderReportStatus(errors.length > 0
      ? `${errors.length} source${errors.length === 1 ? "" : "s"} could not be collected`
      : `${allImages.length} service${allImages.length === 1 ? "" : "s"}`,
    errors);
    updatedAt.textContent = `Updated ${new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit"
    }).format(new Date())}`;
  } catch {
    reportStatus.dataset.state = "error";
    renderReportStatus("Could not load the image report. Please try again.");
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
      renderReportStatus("Could not copy image reference. Check clipboard permissions and try again.");
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
    const response = await fetch("auth/logout", {
      method: "POST",
      credentials: "same-origin"
    });

    if (!response.ok) {
      reportStatus.dataset.state = "error";
      renderReportStatus("Could not sign out. Please try again.");
      return;
    }

    window.location.replace("login.html");
  } catch {
    reportStatus.dataset.state = "error";
    renderReportStatus("Could not reach the report service. Please try again.");
  } finally {
    signOutButton.disabled = false;
  }
});

loadReport();
