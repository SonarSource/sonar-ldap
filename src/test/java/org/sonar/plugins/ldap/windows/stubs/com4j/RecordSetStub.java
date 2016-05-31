/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.ldap.windows.stubs.com4j;

import com.google.common.base.Preconditions;
import com4j.Com4jObject;
import com4j.ComThread;
import com4j.EventCookie;
import com4j.typelibs.ado20.AffectEnum;
import com4j.typelibs.ado20.CompareEnum;
import com4j.typelibs.ado20.CursorLocationEnum;
import com4j.typelibs.ado20.CursorOptionEnum;
import com4j.typelibs.ado20.CursorTypeEnum;
import com4j.typelibs.ado20.EditModeEnum;
import com4j.typelibs.ado20.Fields;
import com4j.typelibs.ado20.LockTypeEnum;
import com4j.typelibs.ado20.MarshalOptionsEnum;
import com4j.typelibs.ado20.PersistFormatEnum;
import com4j.typelibs.ado20.PositionEnum;
import com4j.typelibs.ado20.Properties;
import com4j.typelibs.ado20.Property;
import com4j.typelibs.ado20.ResyncEnum;
import com4j.typelibs.ado20.SearchDirection;
import com4j.typelibs.ado20.StringFormatEnum;
import com4j.typelibs.ado20._Recordset;
import java.util.Collection;
import java.util.Iterator;

/**
 * Partial implementation of {@link _Recordset} for testing purpose
 */
public class RecordSetStub implements _Recordset {
  private Iterator<Fields> fieldsIterator;
  private Fields currentFields;
  private int disposeInvocationCount;
  private int closeInvocationCount;

  public RecordSetStub(Collection<Fields> records) {
    Preconditions.checkNotNull(records, "records is null");

    this.fieldsIterator = records.iterator();
    currentFields = this.fieldsIterator.hasNext() ? this.fieldsIterator.next() : null;
    disposeInvocationCount = 0;
    closeInvocationCount = 0;
  }

  public int getDisposeInvocationCount() {
    return disposeInvocationCount;
  }

  public int getCloseInvocationCount() {
    return closeInvocationCount;
  }

  @Override
  public void cancel() {

  }

  @Override
  public Com4jObject dataSource() {
    return null;
  }

  @Override
  public void dataSource(Com4jObject ppunkDataSource) {

  }

  @Override
  public void save(String fileName, PersistFormatEnum persistFormat) {

  }

  @Override
  public Com4jObject activeCommand() {
    return null;
  }

  @Override
  public void stayInSync(boolean pbStayInSync) {

  }

  @Override
  public boolean stayInSync() {
    return false;
  }

  @Override
  public String getString(StringFormatEnum stringFormat, int numRows, String columnDelimeter, String rowDelimeter, String nullExpr) {
    return null;
  }

  @Override
  public String dataMember() {
    return null;
  }

  @Override
  public void dataMember(String pbstrDataMember) {

  }

  @Override
  public CompareEnum compareBookmarks(Object bookmark1, Object bookmark2) {
    return null;
  }

  @Override
  public _Recordset clone(LockTypeEnum lockType) {
    return null;
  }

  @Override
  public void resync(AffectEnum affectRecords, ResyncEnum resyncValues) {

  }

  @Override
  public PositionEnum absolutePosition() {
    return null;
  }

  @Override
  public void absolutePosition(PositionEnum pl) {

  }

  @Override
  public void activeConnection(Com4jObject pvar) {

  }

  @Override
  public Object activeConnection() {
    return null;
  }

  @Override
  public boolean bof() {
    return false;
  }

  @Override
  public Object bookmark() {
    return null;
  }

  @Override
  public void bookmark(Object pvBookmark) {

  }

  @Override
  public int cacheSize() {
    return 0;
  }

  @Override
  public void cacheSize(int pl) {

  }

  @Override
  public CursorTypeEnum cursorType() {
    return null;
  }

  @Override
  public void cursorType(CursorTypeEnum plCursorType) {

  }

  @Override
  public boolean eof() {
    return currentFields == null;
  }

  @Override
  public Fields fields() {
    return currentFields;
  }

  @Override
  public LockTypeEnum lockType() {
    return null;
  }

  @Override
  public void lockType(LockTypeEnum plLockType) {

  }

  @Override
  public int maxRecords() {
    return 0;
  }

  @Override
  public void maxRecords(int plMaxRecords) {

  }

  @Override
  public int recordCount() {
    return 0;
  }

  @Override
  public void source(Com4jObject pvSource) {

  }

  @Override
  public Object source() {
    return null;
  }

  @Override
  public void addNew(Object fieldList, Object values) {

  }

  @Override
  public void cancelUpdate() {

  }

  @Override
  public void close() {
    closeInvocationCount++;
  }

  @Override
  public void delete(AffectEnum affectRecords) {

  }

  @Override
  public Object getRows(int rows, Object start, Object fields) {
    return null;
  }

  @Override
  public void move(int numRecords, Object start) {

  }

  @Override
  public void moveNext() {
    currentFields = fieldsIterator.hasNext() ? fieldsIterator.next() : null;
  }

  @Override
  public void movePrevious() {

  }

  @Override
  public void moveFirst() {

  }

  @Override
  public void moveLast() {

  }

  @Override
  public void open(Object source, Object activeConnection, CursorTypeEnum cursorType, LockTypeEnum lockType, int options) {

  }

  @Override
  public void requery(int options) {

  }

  @Override
  public void _xResync(AffectEnum affectRecords) {

  }

  @Override
  public void update(Object fields, Object values) {

  }

  @Override
  public PositionEnum absolutePage() {
    return null;
  }

  @Override
  public void absolutePage(PositionEnum pl) {

  }

  @Override
  public EditModeEnum editMode() {
    return null;
  }

  @Override
  public Object filter() {
    return null;
  }

  @Override
  public void filter(Object criteria) {

  }

  @Override
  public int pageCount() {
    return 0;
  }

  @Override
  public int pageSize() {
    return 0;
  }

  @Override
  public void pageSize(int pl) {

  }

  @Override
  public String sort() {
    return null;
  }

  @Override
  public void sort(String criteria) {

  }

  @Override
  public int status() {
    return 0;
  }

  @Override
  public int state() {
    return 0;
  }

  @Override
  public _Recordset _xClone() {
    return null;
  }

  @Override
  public void updateBatch(AffectEnum affectRecords) {

  }

  @Override
  public void cancelBatch(AffectEnum affectRecords) {

  }

  @Override
  public CursorLocationEnum cursorLocation() {
    return null;
  }

  @Override
  public void cursorLocation(CursorLocationEnum plCursorLoc) {

  }

  @Override
  public _Recordset nextRecordset(Object recordsAffected) {
    return null;
  }

  @Override
  public boolean supports(CursorOptionEnum cursorOptions) {
    return false;
  }

  @Override
  public Object collect(Object index) {
    return null;
  }

  @Override
  public void collect(Object index, Object pvar) {

  }

  @Override
  public MarshalOptionsEnum marshalOptions() {
    return null;
  }

  @Override
  public void marshalOptions(MarshalOptionsEnum peMarshal) {

  }

  @Override
  public void find(String criteria, int skipRecords, SearchDirection searchDirection, Object start) {

  }

  @Override
  public Properties properties() {
    return null;
  }

  @Override
  public Property properties(Object index) {
    return null;
  }

  @Override
  public int getPtr() {
    return 0;
  }

  @Override
  public long getPointer() {
    return 0;
  }

  @Override
  public long getIUnknownPointer() {
    return 0;
  }

  @Override
  public ComThread getComThread() {
    return null;
  }

  @Override
  public void dispose() {
    disposeInvocationCount++;
  }

  @Override
  public <T extends Com4jObject> boolean is(Class<T> comInterface) {
    return false;
  }

  @Override
  public <T extends Com4jObject> T queryInterface(Class<T> comInterface) {
    return null;
  }

  @Override
  public <T> EventCookie advise(Class<T> eventInterface, T receiver) {
    return null;
  }

  @Override
  public void setName(String name) {

  }
}
