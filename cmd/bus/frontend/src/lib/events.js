import { Events } from '@wailsio/runtime';

export function EventsOn(name, callback) {
  return Events.On(name, (event) => {
    const data = event?.data;
    if (Array.isArray(data) && callback.length > 1) {
      callback(...data);
    } else if (data === undefined) {
      callback();
    } else {
      callback(data);
    }
  });
}

export function EventsOff(name) {
  Events.Off(name);
}
