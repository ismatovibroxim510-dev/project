"use client";

import "leaflet/dist/leaflet.css";
import { useEffect, useRef } from "react";

/**
 * Small OpenStreetMap map. Leaflet is bundled with the app (no third-party script),
 * so the only external resource is map tiles from tile.openstreetmap.org, which our
 * CSP allows as images. No popups/tooltips: Leaflet would render those as HTML.
 */
export function ServerMap({ latitude, longitude, label }: { latitude: number; longitude: number; label: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    let map: import("leaflet").Map | undefined;
    void import("leaflet").then((L) => {
      if (cancelled || !ref.current) return;
      map = L.map(ref.current, { scrollWheelZoom: false, attributionControl: true }).setView([latitude, longitude], 4);
      L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 18,
        attribution:
          '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
      }).addTo(map);
      L.circleMarker([latitude, longitude], {
        radius: 9,
        color: "#c7d2fe",
        weight: 2,
        fillColor: "#6366f1",
        fillOpacity: 0.85,
      }).addTo(map);
    });
    return () => {
      cancelled = true;
      map?.remove();
    };
  }, [latitude, longitude]);

  return (
    <div
      ref={ref}
      role="img"
      aria-label={`Map showing the approximate server location: ${label}`}
      className="server-map h-56 w-full overflow-hidden rounded-xl ring-1 ring-white/[0.08] sm:h-64"
    />
  );
}
