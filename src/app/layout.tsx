import type { Metadata } from "next";
import { Space_Grotesk, Source_Serif_4, IBM_Plex_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

const sourceSerif = Source_Serif_4({
  variable: "--font-source-serif",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-ibm-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  title: "TRUSTVEX — Website Trust & Risk Intelligence",
  description:
    "Submit a URL and get an explainable, evidence-based risk assessment: URL structure, DNS, TLS, redirects, page content, and reputation signals combined into one transparent report.",
  authors: [{ name: "Zeenathul Virdha Musawwir" }],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body
        className={`${spaceGrotesk.variable} ${sourceSerif.variable} ${plexMono.variable} antialiased`}
      >
        <div className="min-h-screen flex flex-col">
          <header className="sticky top-0 z-40 border-b border-border-hairline bg-bg-base/85 backdrop-blur-md">
            <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between">
              <Link
                href="/"
                className="font-display font-bold text-lg tracking-tight text-ink transition-opacity hover:opacity-80"
              >
                TRUST<span className="text-signal-clear">VEX</span>
              </Link>
              <nav className="flex gap-6 font-display text-sm">
                <Link href="/" className="text-ink-muted hover:text-ink transition-colors">
                  Scan
                </Link>
                <Link href="/history" className="text-ink-muted hover:text-ink transition-colors">
                  History
                </Link>
              </nav>
            </div>
          </header>

          <main className="flex-1">{children}</main>

          <footer className="border-t border-border-hairline">
            <div className="mx-auto max-w-5xl px-6 py-10">
              <div className="grid md:grid-cols-2 gap-8 md:gap-12">
                {/* Left: disclaimer */}
                <div>
                  <p className="font-display font-semibold text-xs tracking-[0.18em] uppercase text-ink-muted mb-3">
                    About
                  </p>
                  <p className="font-body text-xs text-ink-muted leading-relaxed">
                    TRUSTVEX produces an automated, evidence-based estimate —
                    not a guarantee. It cannot confirm a site is safe, and a
                    low score does not certify one is malicious. Every signal
                    is shown with its evidence; every failure is reported
                    honestly.
                  </p>
                </div>

                {/* Right: author + animated links */}
                <div>
                  <p className="font-display font-semibold text-xs tracking-[0.18em] uppercase text-ink-muted mb-3">
                    Built by
                  </p>
                  <p className="author-glow font-display font-medium text-sm">
                    Zeenathul Virdha Musawwir
                  </p>
                  <p className="font-body text-xs text-ink-muted mt-1">
                    Full-stack engineering · cybersecurity · machine learning
                  </p>

                  <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2">
                    <FooterLink href="https://www.linkedin.com/in/zeenathul-virdha-musawwir-123b60329/" label="LinkedIn" />
                    <FooterLink href="https://github.com/mmsvirdha" label="GitHub" />
                    <FooterLink href="https://virdhamusawwirportfolio.netlify.app" label="Portfolio" />
                  </div>

                  <div className="mt-4 flex flex-col gap-1.5">
                    <a
                      href="mailto:zeenathulvirdha.it@gmail.com"
                      className="contact-link font-data text-xs inline-flex items-center gap-2"
                    >
                      <span className="contact-icon">✉</span>
                      <span>zeenathulvirdha.it@gmail.com</span>
                    </a>
                    <a
                      href="tel:+94750816026"
                      className="contact-link font-data text-xs inline-flex items-center gap-2"
                    >
                      <span className="contact-icon">☎</span>
                      <span>+94 75 081 6026</span>
                    </a>
                  </div>
                </div>
              </div>

              <div className="mt-10 pt-6 border-t border-border-hairline flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <p className="font-data text-xs text-ink-muted">
                  © {new Date().getFullYear()} Zeenathul Virdha Musawwir. All
                  rights reserved.
                </p>
                <p className="font-data text-xs text-ink-muted inline-flex items-center gap-2">
                  <span className="pulse-dot" />
                  TRUSTVEX v1.0
                </p>
              </div>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}

function FooterLink({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="footer-link font-display text-xs inline-flex items-center gap-1"
    >
      <span className="footer-link-underline">{label}</span>
      <span aria-hidden className="footer-link-arrow text-[10px]">↗</span>
    </a>
  );
}