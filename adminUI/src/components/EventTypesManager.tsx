import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Switch } from './ui/switch';
import type { EventFamily } from '../types';

interface EventTypesManagerProps {
  eventFamilies: EventFamily[];
  setEventFamilies: (families: EventFamily[]) => void;
}

export function EventTypesManager({ eventFamilies, setEventFamilies }: EventTypesManagerProps) {
  const toggleEvent = (eventUri: string) => {
    setEventFamilies(eventFamilies.map(family => ({
      ...family,
      events: family.events.map(event =>
        event.uri === eventUri ? { ...event, enabled: !event.enabled } : event
      ),
    })));
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mb-2">Event Types</h1>
        <p className="text-muted-foreground">Configure supported event types for CAEP and RISC</p>
      </div>

      <div className="space-y-6">
        {eventFamilies.map((family) => (
          <Card key={family.uri}>
            <CardHeader>
              <CardTitle>{family.name}</CardTitle>
              <p className="text-sm text-muted-foreground">{family.description}</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {family.events.map((event) => (
                  <div key={event.uri} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <p className="text-sm">{event.name}</p>
                      <p className="text-xs text-muted-foreground">{event.description}</p>
                    </div>
                    <Switch
                      checked={event.enabled}
                      onCheckedChange={() => toggleEvent(event.uri)}
                    />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
