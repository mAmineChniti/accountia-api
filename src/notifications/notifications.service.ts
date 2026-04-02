import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Notification, NotificationType } from './schemas/notification.schema';
import { NotificationsGateway } from './notifications.gateway';

export interface NotificationEvent {
  id: string;
  type: NotificationType;
  message: string;
  payload: Record<string, unknown>;
  targetBusinessId?: string;
  targetUserEmail?: string;
  createdAt: Date;
}

@Injectable()
export class NotificationsService {
  constructor(
    @InjectModel(Notification.name)
    private notificationModel: Model<Notification>,
    private notificationsGateway: NotificationsGateway
  ) {}

  async createNotification(data: {
    type: NotificationType;
    message: string;
    payload?: Record<string, unknown>;
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

    const event: NotificationEvent = {
      id: saved._id.toString(),
      type: saved.type,
      message: saved.message,
      payload: saved.payload,
      targetBusinessId: saved.targetBusinessId,
      targetUserEmail: saved.targetUserEmail,
      createdAt: saved.createdAt,
    };

    // Emit to WebSocket gateway
    this.notificationsGateway.emitNotification(event);
  }

  async getUnread(
    businessId?: string,
    userEmail?: string
  ): Promise<Notification[]> {
    const query = this.buildFilters(businessId, userEmail, true);

    return (await this.notificationModel
      .find({ ...query })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean()
      .exec()) as Notification[];
  }

  async getRecent(
    businessId?: string,
    userEmail?: string
  ): Promise<Notification[]> {
    const query = this.buildFilters(businessId, userEmail, false);

    return (await this.notificationModel
      .find({ ...query })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean()
      .exec()) as Notification[];
  }

  async markAsRead(id: string): Promise<void> {
    await this.notificationModel.findByIdAndUpdate(id, { isRead: true });
  }

  async markAllAsRead(businessId?: string, userEmail?: string): Promise<void> {
    const query = this.buildFilters(businessId, userEmail, true);
    await this.notificationModel.updateMany({ ...query }, { isRead: true });
  }

  private buildFilters(
    businessId?: string,
    userEmail?: string,
    addReadFilter = false
  ): Record<string, unknown> {
    const baseFilter: Record<string, unknown> = {};

    if (addReadFilter) {
      baseFilter.isRead = false;
    }

    if (businessId) {
      baseFilter.targetBusinessId = businessId;
    } else if (userEmail) {
      baseFilter.targetUserEmail = userEmail;
    } else {
      baseFilter.targetBusinessId = { $exists: false };
      baseFilter.targetUserEmail = { $exists: false };
    }

    return baseFilter;
  }
}
