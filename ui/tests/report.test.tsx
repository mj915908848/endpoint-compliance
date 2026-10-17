import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SensitiveFileTable } from "../src/components/report";
import type { Evidence } from "../src/types";

const hits: Evidence[] = Array.from({ length: 45 }, (_, i) => ({
  productId: "rule-1",
  productName: "机密文件",
  kind: "SensitiveFile",
  objectKey: `C:\\Users\\a\\Documents\\机密资料-${i}.xlsx`,
  source: "S-1-5-21-1",
  summary: "命中关键词“机密”",
  userSid: "S-1-5-21-1",
  confirmed: true,
  collectedAt: null,
}));

describe("report tables", () => {
  it("brings the section back into view when the page changes", async () => {
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    render(
      <section>
        <SensitiveFileTable values={hits} complete />
      </section>,
    );
    expect(screen.getByText("C:\\Users\\a\\Documents\\机密资料-0.xlsx")).toBeTruthy();
    await userEvent.click(screen.getByTitle("2"));
    expect(screen.getByText("C:\\Users\\a\\Documents\\机密资料-20.xlsx")).toBeTruthy();
    expect(scroll).toHaveBeenCalledWith({ block: "start" });
    expect(scroll.mock.contexts[0]).toBeInstanceOf(HTMLElement);
    expect((scroll.mock.contexts[0] as HTMLElement).tagName).toBe("SECTION");
  });
});
