export interface AccessLocation {
  lat: number;
  lng: number;
}

export interface PolicyCheckResult {
  allowed: boolean;
  reason?: string;
  details?: {
    workingHoursValid?: boolean;
    geofenceValid?: boolean;
    velocityValid?: boolean;
    mfaValid?: boolean;
  };
}

