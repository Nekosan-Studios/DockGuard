import { writable } from 'svelte/store';

export type SettingSource = 'env' | 'db' | 'default' | 'unknown';

export interface Setting {
    key: string;
    value: string;
    source: SettingSource;
    editable: boolean;
}

export interface SettingsMap {
    [key: string]: Setting;
}

function createSettingsStore() {
    const { subscribe, set, update } = writable<SettingsMap>({});

    return {
        subscribe,
        set,
        update,
        async fetch() {
            try {
                const response = await fetch('/api/settings');
                if (response.ok) {
                    const data = await response.json();
                    set(data);
                } else {
                    console.error('Failed to fetch settings:', response.statusText);
                }
            } catch (err) {
                console.error('Error fetching settings:', err);
            }
        },
        async updateSettings(updates: Record<string, string>) {
            try {
                const response = await fetch('/api/settings', {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ settings: updates })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Failed to update settings');
                }

                // Re-fetch to get the source of truth
                await this.fetch();
                return true;
            } catch (err) {
                console.error('Error updating settings:', err);
                throw err;
            }
        }
    };
}

export const settings = createSettingsStore();
