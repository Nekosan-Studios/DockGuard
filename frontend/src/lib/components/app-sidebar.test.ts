import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import AppSidebarTestWrapper from "./app-sidebar-test-wrapper.svelte";

describe("app-sidebar", () => {
  it("renders the application branding", () => {
    render(AppSidebarTestWrapper);

    expect(screen.getByText("DockGuard")).toBeInTheDocument();
    expect(screen.getByText("Security Monitor")).toBeInTheDocument();
    const logo = screen.getByAltText("DockGuard Logo");
    expect(logo).toHaveAttribute("src", "/logo.png");
  });

  it("renders all 5 main navigation links", () => {
    render(AppSidebarTestWrapper);

    const dashboardLink = screen.getByRole("link", { name: /Dashboard/i });
    expect(dashboardLink).toHaveAttribute("href", "/");

    const containersLink = screen.getByRole("link", { name: /Containers/i });
    expect(containersLink).toHaveAttribute("href", "/containers");

    const vulnsLink = screen.getByRole("link", { name: /Vulnerabilities/i });
    expect(vulnsLink).toHaveAttribute("href", "/vulnerabilities");

    const tasksLink = screen.getByRole("link", { name: /Tasks/i });
    expect(tasksLink).toHaveAttribute("href", "/tasks");

    const settingsLink = screen.getByRole("link", { name: /Settings/i });
    expect(settingsLink).toHaveAttribute("href", "/settings");
  });
});
