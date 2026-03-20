export interface NotificationChannel {
  id: number;
  name: string;
  apprise_url: string;
  enabled: boolean;
  notify_urgent: boolean;
  notify_all_new: boolean;
  notify_digest: boolean;
  notify_kev: boolean;
  notify_eol: boolean;
  notify_scan_failure: boolean;
  created_at: string;
  updated_at: string;
}

export interface NotificationLogEntry {
  id: number;
  channel_id: number;
  channel_name: string;
  notification_type: string;
  title: string;
  body: string;
  status: string;
  error_message: string | null;
  created_at: string;
}

class NotificationStore {
  channels = $state.raw<NotificationChannel[]>([]);
  log = $state.raw<NotificationLogEntry[]>([]);
  logTotal = $state.raw<number>(0);

  async fetchChannels() {
    try {
      const res = await fetch("/api/notifications/channels");
      if (res.ok) {
        this.channels = await res.json();
      }
    } catch (err) {
      console.error("Error fetching notification channels:", err);
    }
  }

  async createChannel(
    data: Omit<NotificationChannel, "id" | "created_at" | "updated_at">
  ): Promise<NotificationChannel | null> {
    const res = await fetch("/api/notifications/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to create channel");
    }
    const channel = await res.json();
    await this.fetchChannels();
    return channel;
  }

  async updateChannel(
    id: number,
    data: Partial<NotificationChannel>
  ): Promise<void> {
    const res = await fetch(`/api/notifications/channels/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to update channel");
    }
    await this.fetchChannels();
  }

  async deleteChannel(id: number): Promise<void> {
    const res = await fetch(`/api/notifications/channels/${id}`, {
      method: "DELETE",
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to delete channel");
    }
    await this.fetchChannels();
  }

  async testChannel(id: number): Promise<void> {
    const res = await fetch(`/api/notifications/channels/${id}/test`, {
      method: "POST",
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Test notification failed");
    }
  }

  async fetchLog(page: number = 1, pageSize: number = 50) {
    try {
      const res = await fetch(
        `/api/notifications/log?page=${page}&page_size=${pageSize}`
      );
      if (res.ok) {
        const data = await res.json();
        this.log = data.entries;
        this.logTotal = data.total;
      }
    } catch (err) {
      console.error("Error fetching notification log:", err);
    }
  }
}

export const notifications = new NotificationStore();
