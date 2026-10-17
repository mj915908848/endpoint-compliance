import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "../src/components";
import { Providers } from "../src/providers";

function Broken(): never {
  throw new Error("blockDomains is null");
}

describe("error boundary", () => {
  it("shows a page that fails to render as an error instead of a blank window", () => {
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <Providers>
        <ErrorBoundary>
          <Broken />
        </ErrorBoundary>
      </Providers>,
    );
    expect(screen.getByText("页面显示出错")).toBeTruthy();
    expect(screen.getByText(/blockDomains is null/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "重新加载" })).toBeTruthy();
    quiet.mockRestore();
  });
});
