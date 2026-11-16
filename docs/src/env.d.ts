/// <reference types="astro/client" />

interface ImportMetaEnv {
  // Amplitude project API key for the docs site. Unset: no analytics.
  readonly PUBLIC_AMPLITUDE_API_KEY?: string
  // 'EU' for a project in Amplitude's EU data center; anything else means US.
  readonly PUBLIC_AMPLITUDE_SERVER_ZONE?: string
}
