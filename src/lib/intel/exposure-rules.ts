/** Score penalties from Shodan exposure data (shared by the scorer and the About page). */
export const EXPOSURE_RULES = {
  databasePort: 5,
  remoteAdminPort: 3,
  portCap: 12,
  someCves: 3,
  manyCves: 6,
  manyCvesThreshold: 5,
  totalCap: 15,
};
