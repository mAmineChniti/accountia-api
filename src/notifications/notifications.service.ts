import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Subject, Observable } from 'rxjs';
import {
  Notification,
  NotificationType,
} from './schemas/notification.schema';

export interface NotificationEvent {
  id: string;
  type: NotificationType;
  message: string;
  payload: Record<string, any>;
  targetBusinessId?: string;
  targetUserEmail?: string;
  createdAt: Date;
}

@Injectable()
export class NotificationsService {
  private eventSubject = new Subject<NotificationEvent>();

  constructor(
    @InjectModel(Notification.name)
    private notificationModel: Model<Notification>
  ) {}

  async createNotification(data: {
    type: NotificationType;
    message: string;
    payload?: Record<string, any>;
    targetBusinessId?: string;
    targetUserEmail?: string;
  }): Promise<void> {
    const notification = new this.notificationModel({
      type: data.type,
      message: data.message,
      payload: data.payload ?? {},
      targetBusinessId: data.targetBusinessId,
      targetUserEmail: data.targetUserEmail,
      isRead: false,
    });
    const saved = await notification.save();

    // Emit to SSE stream
    this.eventSubject.next({
      id: saved._id.toString(),
      type: saved.type,
      message: saved.message,
      payload: saved.payload,
      targetBusinessId: saved.targetBusinessId,
      targetUserEmail: saved.targetUserEmail,
      createdAt: saved.createdAt,
    });
  }

  /**
   * Returns an SSE-compatible Observable for the controller.
   * If businessId or userEmail is provided, only sends events targeted to that business/user.
   */
  getEventStream(businessId?: string, userEmail?: string): Observable<MessageEvent> {
    return this.eventSubject.pipe(
      (source) => new Observable<MessageEvent>((observer) => {
        const subscription = source.subscribe({
          next: (event) => {
            // Logic:
            // 1. If businessId provided: deliver if event matched businessId
            // 2. If userEmail provided: deliver if event matched userEmail
            // 3. Admin (no businessId/userEmail): deliver if NO targetBusinessId and NO targetUserEmail
            
            if (businessId) {
              if (event.targetBusinessId === businessId) {
                observer.next({ data: event } as MessageEvent);
              }
            } else if (userEmail) {
              if (event.targetUserEmail === userEmail) {
                observer.next({ data: event } as MessageEvent);
              }
            } else {
              // Admin: global events
              if (!event.targetBusinessId && !event.targetUserEmail) {
                observer.next({ data: event } as MessageEvent);
              }
            }
          },
          error: (err) => observer.error(err),
          complete: () => observer.complete(),
        });
        return () => subscription.unsubscribe();
      })
    );
  }

  async getUnread(businessId?: string, userEmail?: string): Promise<Notification[]> {
    const filter: any = { isRead: false };
    if (businessId) {
      filter.targetBusinessId = businessId;
    } else if (userEmail) {
      filter.targetUserEmail = userEmail;
    } else {
      filter.targetBusinessId = { $exists: false }; // Admins see global
      filter.targetUserEmail = { $exists: false };
    }
    
    return this.notificationModel
      .find(filter)
      .sort({ createdAt: -1 })
      .limit(20)
      .lean()
      .exec() as unknown as Notification[];
  }

  async getRecent(businessId?: string, userEmail?: string): Promise<Notification[]> {
    const filter: any = {};
    if (businessId) {
      filter.targetBusinessId = businessId;
    } else if (userEmail) {
      filter.targetUserEmail = userEmail;
    } else {
      filter.targetBusinessId = { $exists: false }; // Admins see global
      filter.targetUserEmail = { $exists: false };
    }

    return this.notificationModel
      .find(filter)
      .sort({ createdAt: -1 })
      .limit(20)
      .lean()
      .exec() as unknown as Notification[];
  }

  async markAsRead(id: string): Promise<void> {
    await this.notificationModel.findByIdAndUpdate(id, { isRead: true });
  }

  async markAllAsRead(businessId?: string, userEmail?: string): Promise<void> {
    const filter: any = { isRead: false };
    if (businessId) {
      filter.targetBusinessId = businessId;
    } else if (userEmail) {
      filter.targetUserEmail = userEmail;
    } else {
      filter.targetBusinessId = { $exists: false };
      filter.targetUserEmail = { $exists: false };
    }
    await this.notificationModel.updateMany(filter, { isRead: true });
  }
}
