import { render, screen } from "@testing-library/svelte";
import { describe, it, expect } from "vitest";
import Page from "./+page.svelte";

function makeData(overrides = {}) {
  return {
    tasks: [],
    total: 0,
    currentPage: 1,
    apiError: false,
    ...overrides,
  };
}

describe("Tasks page", () => {
  it("renders the page heading", () => {
    render(Page, { data: makeData() });
    expect(screen.getByRole("heading", { name: "Tasks" })).toBeInTheDocument();
  });

  it("shows empty state when there are no tasks", () => {
    render(Page, { data: makeData() });
    expect(
      screen.getByText("No recent tasks in the database.")
    ).toBeInTheDocument();
  });

  it("shows API error banner when apiError is true", () => {
    render(Page, { data: makeData({ apiError: true }) });
    expect(screen.getByText("Unexpected Error")).toBeInTheDocument();
  });

  it("renders task table headers when tasks are present", () => {
    const task = {
      id: 1,
      task_name: "scan_image",
      status: "completed",
      created_at: "2024-01-01T00:00:00Z",
      finished_at: "2024-01-01T00:01:00Z",
      error_message: null,
      result_details: "Scanned successfully",
    };
    render(Page, { data: makeData({ tasks: [task] }) });
    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getByText("Task Name")).toBeInTheDocument();
    expect(screen.getByText("Created")).toBeInTheDocument();
    expect(screen.getByText("Finished")).toBeInTheDocument();
  });

  it("renders task name and status badge when tasks are present", () => {
    const task = {
      id: 1,
      task_name: "scan_image",
      status: "running",
      created_at: "2024-01-01T00:00:00Z",
      finished_at: null,
      error_message: null,
      result_details: null,
    };
    render(Page, { data: makeData({ tasks: [task] }) });
    expect(screen.getByText("scan_image")).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
  });
});
