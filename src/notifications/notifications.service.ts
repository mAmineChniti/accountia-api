import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Subject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import {
  Notification,
  NotificationType,
} from './schemas/notification.schema';

export interface NotificationEvent {
  id: string;
  type: NotificationType;
  message: string;
  payload: Record<string, any>;
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
  }): Promise<void> {
    const notification = new this.notificationModel({
      type: data.type,
      message: data.message,
      payload: data.payload ?? {},
      isRead: false,
    });
    const saved = await notification.save();

    // Emit to SSE stream
    this.eventSubject.next({
      id: saved._id.toString(),
      type: saved.type,
      message: saved.message,
      payload: saved.payload,
      createdAt: saved.createdAt,
    });
  }

  /**
   * Returns an SSE-compatible Observable for the controller.
   */
  getEventStream(): Observable<MessageEvent> {
    return this.eventSubject.pipe(
      map(
        (event) =>
          ({
            data: event,
          }) as MessageEvent
      )
    );
  }

  async getUnread(): Promise<Notification[]> {
    return this.notificationModel
      .find({ isRead: false })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean()
      .exec() as unknown as Notification[];
  }

  async getRecent(): Promise<Notification[]> {
    return this.notificationModel
      .find()
      .sort({ createdAt: -1 })
      .limit(20)
      .lean()
      .exec() as unknown as Notification[];
  }

  async markAsRead(id: string): Promise<void> {
    await this.notificationModel.findByIdAndUpdate(id, { isRead: true });
  }

  async markAllAsRead(): Promise<void> {
    await this.notificationModel.updateMany({ isRead: false }, { isRead: true });
  }
}
