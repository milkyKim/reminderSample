import Reminder from '../models/Reminder';
import mongoose from 'mongoose';

//서비스 로직 구현 시 인자로 받는 것에 대한 interface를 미리 만들어주는 것이 좋다.
export interface reminderCreateInput {
  title: string;
  date: string;
  sendDate: string;
  isAlarm: boolean;
  isImportant: boolean;
  userIdx: string;
  year: string;
  month: string;
}

export interface reminderFindInput {
  userIdx: string;
}

export interface reminderOncomingFindInput {
  userIdx: string;
  start: string; //시스템 시간 now() 이후.
}

export interface reminderMonthFindInput {
  userIdx: string;
  year: string;
  month: string;
}
export interface reminderFindInputByReminderId {
  reminderIdx: string;
}

const saveReminder = (data: reminderCreateInput) => {
  return Reminder.create(data);
};

const findReminder = (data: reminderFindInput) => {
  const result = Reminder.find({
    userIdx: data.userIdx,
  }).sort({ date: 1 }); //가까운 순으로 정렬
  return result;
};

const findDetailReminder = (data: reminderFindInputByReminderId) => {
  const result = Reminder.find(
    {
      _id: data.reminderIdx,
    },
    { _id: 1, title: 1, date: 1, sendDate: 1, isAlarm: 1, isImportant: 1 }
  ).sort({ date: 1 }); //가까운 순으로 정렬
  return result;
};

const findMonthReminder = (data: reminderMonthFindInput) => {
  const result = Reminder.find(
    {
      userIdx: data.userIdx,
      year: data.year,
      month: data.month,
    },
    { _id: 1, title: 1, date: 1, isAlarm: 1, isImportant: 1 }
  ).sort({ date: 1 }); //가까운 순으로 정렬
  return result;
};

// 다가오는 리마인더 조회
const findReminderOncoming = (data: reminderOncomingFindInput) => {
  const result = Reminder.find(
    {
      userIdx: data.userIdx,
      date: { $gte: data.start },
    },
    { _id: 1, title: 1, date: 1, isImportant: 1 }
  )
    .sort({ date: 1 })
    .limit(2); //가까운 순으로 정렬, 2개만 나오게
  return result;
};

const findReminderbyReminderId = (data: reminderFindInputByReminderId) => {
  return Reminder.findOne({ _id: data.reminderIdx });
};

const deleteReminderbyReminderId = (data: reminderFindInputByReminderId) => {
  return Reminder.deleteOne({ _id: data.reminderIdx });
};

export default {
  saveReminder,
  findReminder,
  findDetailReminder,
  findMonthReminder,
  findReminderbyReminderId,
  findReminderOncoming,
  deleteReminderbyReminderId,
};
