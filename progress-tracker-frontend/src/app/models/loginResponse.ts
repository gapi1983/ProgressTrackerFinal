export interface LoginResponse {
    message:       string;
    requires2FA?:  boolean;   
    mustSetup2FA?: boolean;   
    userId?:       string;
  }