package com.questdb.griffin.engine.functions.osquery;

/*******************************************************************************
 *    ___                  _   ____  ____
 *   / _ \ _   _  ___  ___| |_|  _ \| __ )
 *  | | | | | | |/ _ \/ __| __| | | |  _ \
 *  | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *   \__\_\\__,_|\___||___/\__|____/|____/
 *
 * Copyright (C) 2014-2019 Appsicle
 *
 * This program is free software: you can redistribute it and/or  modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ******************************************************************************/


import com.questdb.cairo.*;
import com.questdb.cairo.sql.Function;
import com.questdb.cairo.sql.NoRandomAccessRecordCursor;
import com.questdb.cairo.sql.Record;
import com.questdb.cairo.sql.RecordMetadata;
import com.questdb.griffin.FunctionFactory;
import com.questdb.griffin.engine.functions.CursorFunction;
import com.questdb.griffin.engine.functions.GenericRecordCursorFactory;
import com.questdb.ql.NullRecord;
import com.questdb.std.IntIntHashMap;
import com.questdb.std.ObjList;
import lombok.SneakyThrows;
import net.melastmohican.osquery.ClientManager;
import org.apache.thrift.transport.TTransportException;
import osquery.extensions.ExtensionManager;
import osquery.extensions.ExtensionResponse;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.questdb.griffin.engine.functions.osquery.OsqueryType.*;

public class OsqueryFunctionFactory implements FunctionFactory {
    private static final IntIntHashMap jdbcToQuestColumnType = new IntIntHashMap();

    static {
        jdbcToQuestColumnType.put(TEXT.ordinal(), ColumnType.STRING);
        jdbcToQuestColumnType.put(INTEGER.ordinal(), ColumnType.INT);
        jdbcToQuestColumnType.put(BIGINT.ordinal(), ColumnType.LONG);
        jdbcToQuestColumnType.put(DOUBLE.ordinal(), ColumnType.DOUBLE);
    }

    private static final NullRecord NULL = NullRecord.INSTANCE;

    @Override
    public String getSignature() {
        return "osquery(S)";
    }

    @Override
    @SneakyThrows
    public Function newInstance(ObjList<Function> args, int position, CairoConfiguration configuration) {
        final String query = String.valueOf(args.getQuick(0).getStr(null));

        ClientManager cm = getClientManager();
        ExtensionManager.Client client = cm.getClient();

        final RecordMetadata metadata = getResultSetMetadata(client, query);
        return new CursorFunction(
                position,
                new GenericRecordCursorFactory(metadata, new OsqueryRecordCursor(cm, client, metadata, query), false)
        );
    }

    private static ClientManager getClientManager() throws IOException, TTransportException {
        ClientManager clientManager =  new ClientManager(ClientManager.SHELL_SOCKET_PATH);
        clientManager.open();
        return clientManager;
    }

    @SneakyThrows
    private RecordMetadata getResultSetMetadata(ExtensionManager.Client client, String query) {
        ExtensionResponse queryColumns = client.getQueryColumns(query);
        if(queryColumns.getStatus().getCode()!=0){
            throw new IllegalStateException(queryColumns.getStatus().getMessage());
        }
        List<Map<String, String>> response = queryColumns.getResponse();

        final GenericRecordMetadata metadata = new GenericRecordMetadata();
        for (Map<String, String> metaRow : response) {
            String columnName = metaRow.keySet().iterator().next();
            String sourceColumnType = metaRow.values().iterator().next();
            OsqueryType osqueryType = OsqueryType.valueOf(sourceColumnType);
            int columnType = jdbcToQuestColumnType.get(osqueryType.ordinal());
            try {
                metadata.add(new TableColumnMetadata(columnName, columnType));
            } catch (CairoException e) {
                throw new IllegalArgumentException("Column name duplication" + columnName);
            }
        }
        return metadata;
    }

    static class OsqueryRecordCursor implements NoRandomAccessRecordCursor {

        private final OsQueryRecord record;

        public OsqueryRecordCursor(ClientManager clientManager, ExtensionManager.Client client, RecordMetadata recordMetadata, String query) {
            record = new OsQueryRecord(clientManager, client, recordMetadata, query);
        }

        @Override
        @SneakyThrows
        public void close() {
            record.close();
        }

        @Override
        public Record getRecord() {
            return record;
        }

        @Override
        public boolean hasNext() {
            return record.next();
        }


        @Override
        public void toTop() {
            record.init();
        }
    }

    static class OsQueryRecord implements Record, Closeable {

        private ClientManager clientManager;
        private ExtensionManager.Client client;
        private String query;
        private final RecordMetadata recordMetadata;
        int row;
        private String[][] rawValues;


        OsQueryRecord(ClientManager clientManager, ExtensionManager.Client client, RecordMetadata recordMetadata, String query) {
            this.clientManager = clientManager;
            this.client = client;
            this.query = query;
            this.recordMetadata = recordMetadata;
        }

        @SneakyThrows
        void init() {
            if(clientManager == null){
                clientManager = getClientManager();
                client = clientManager.getClient();
            }
            ExtensionResponse response = client.query(this.query);
            if(response.getStatus().getCode()!=0){
                throw new IllegalStateException();
            }
            List<Map<String, String>> queryResponse = response.getResponse();
            int columnCount = recordMetadata.getColumnCount();
            rawValues = new String[queryResponse.size()][columnCount];
            for(int rsRow = 0; rsRow < rawValues.length; rsRow++){
                Map<String, String> row = queryResponse.get(rsRow);
                for(int columnIdx=0; columnIdx < columnCount; columnIdx++){
                    String value = row.get(recordMetadata.getColumnName(columnIdx));
                    rawValues[rsRow][columnIdx] = value.isEmpty() ? null: value;
                }
            }
        }

        @Override
        @SneakyThrows
        public int getInt(int col) {
            String rawValue = rawValues[row][col];
            if (rawValue ==null) {
                return NULL.getInt(col);
            }
            return Integer.parseInt(rawValue);
        }

        @Override
        @SneakyThrows
        public long getLong(int col) {
            String rawValue = rawValues[row][col];
            if (rawValue ==null) {
                return NULL.getLong(col);
            }
            return Long.parseLong(rawValue);
        }

        @Override
        public double getDouble(int col) {
            String rawValue = rawValues[row][col];
            if (rawValue ==null) {
                return NULL.getDouble(col);
            }
            return Double.parseDouble(rawValue);
        }

        @Override
        @SneakyThrows
        public CharSequence getStr(int col) {
            return rawValues[row][col];
        }

        @SneakyThrows
        boolean next() {
            if(row>=rawValues.length-1){
                return false;
            }
            row++;
            return true;
        }

        @Override
        public void close() throws IOException {
            try {
                clientManager.close();
            } finally {
                clientManager = null;
                client=null;
                row = 0;
            }
        }
    }
}
