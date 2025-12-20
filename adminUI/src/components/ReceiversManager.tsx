import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Plus, CheckCircle } from 'lucide-react';
import type { Receiver } from '../types';

interface ReceiversManagerProps {
  receivers: Receiver[];
  setReceivers: (receivers: Receiver[]) => void;
}

export function ReceiversManager({ receivers, setReceivers }: ReceiversManagerProps) {
  const verifyReceiver = (id: string) => {
    setReceivers(receivers.map(r =>
      r.id === id ? { ...r, status: 'active', lastVerified: new Date().toISOString() } : r
    ));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="mb-2">Receivers</h1>
          <p className="text-muted-foreground">Manage event receiver endpoints</p>
        </div>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          Add Receiver
        </Button>
      </div>

      <div className="grid gap-4">
        {receivers.map((receiver) => (
          <Card key={receiver.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">{receiver.name}</CardTitle>
                  {receiver.description && (
                    <p className="text-sm text-muted-foreground">{receiver.description}</p>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={
                    receiver.status === 'active' ? 'default' :
                    receiver.status === 'error' ? 'destructive' : 'secondary'
                  }>
                    {receiver.status}
                  </Badge>
                  <Button variant="outline" size="sm" onClick={() => verifyReceiver(receiver.id)}>
                    <CheckCircle className="h-3 w-3 mr-2" />
                    Verify
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 text-sm">
                <div>
                  <p className="text-muted-foreground mb-1">Endpoint</p>
                  <p className="font-mono text-xs break-all">{receiver.endpoint_url}</p>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div>
                    <p className="text-muted-foreground">Verification</p>
                    <p>{receiver.verification_method === 'jwks_uri' ? 'JWKS' : 'mTLS'}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Events Received</p>
                    <p>{receiver.totalEventsReceived.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Streams</p>
                    <p>{receiver.streams.length}</p>
                  </div>
                </div>
                {receiver.lastVerified && (
                  <div>
                    <p className="text-muted-foreground mb-1">Last Verified</p>
                    <p>{new Date(receiver.lastVerified).toLocaleString()}</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
