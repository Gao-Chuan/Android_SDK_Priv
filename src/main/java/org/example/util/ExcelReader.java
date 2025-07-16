package org.example.util;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFColor;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExcelReader {
    public static void parseACellStr(String input) {
        input = input.replace("True", "true").replace("False", "false").replace("None", "null");

        Pattern clazzPattern = Pattern.compile("Java.use\\(\"(.*?)\"\\)");
        Pattern methodPattern = Pattern.compile("\\[\"(.*?)\"\\]");
        Pattern ppArgsPattern = Pattern.compile(", (\\d), (\\{.*?\\}),");

        Matcher clazzMatcher = clazzPattern.matcher(input);
        Matcher methodMatcher = methodPattern.matcher(input);
        Matcher ppArgsMatcher = ppArgsPattern.matcher(input);

        String apiClazzName = clazzMatcher.find() ? clazzMatcher.group(1) : null;
        String apiMethodName = methodMatcher.find() ? methodMatcher.group(1) : null;

        System.out.println("apiClazzName = " + apiClazzName);
        System.out.println("apiMethodName = " + apiMethodName);

        Map<Integer, Object> ppArgs = new HashMap<>();
        if (ppArgsMatcher.find()) {
            int key = Integer.parseInt(ppArgsMatcher.group(1));
            System.out.println("key:" + key);
            String ppArgsStr = ppArgsMatcher.group(2).substring(1, ppArgsMatcher.group(2).length() - 1);

            String[] ppArgsPairs = ppArgsStr.split(", ");
            for (String pair : ppArgsPairs) {
                String[] keyValue = pair.split(": ");
                Object value;
                if (keyValue.length < 2){
                    System.out.println("The wrong keyv:" + keyValue);
                }
                if (keyValue[1].equalsIgnoreCase("null")) {
                    value = null;
                } else if (keyValue[1].equalsIgnoreCase("true") || keyValue[1].equalsIgnoreCase("false")) {
                    value = Boolean.parseBoolean(keyValue[1]);
                } else {
                    try {
                        value = Integer.parseInt(keyValue[1]);
                    } catch (NumberFormatException e) {
                        value = keyValue[1].replaceAll("\"", "");
                    }
                }

                ppArgs.put(key, value);
            }
        }
        System.out.println("ppArgs = " + ppArgs);
    }


    public static void main(String[] args) {
        try {
            FileInputStream excelFile = new FileInputStream(new File("res/Priv_impl.xlsx"));
            Workbook workbook = new XSSFWorkbook(excelFile);
            Sheet datatypeSheet = workbook.getSheet("Copy of SDKs API list");
            if (datatypeSheet == null) {
                throw new IllegalArgumentException("Sheet not found in workbook");
            }

            List<String> columnNames = new ArrayList<>();
            int rowCount = 0;
            Iterator<Row> iterator = datatypeSheet.iterator();

            while (iterator.hasNext() && rowCount < 14) {
                Row currentRow = iterator.next();
                Iterator<Cell> cellIterator = currentRow.iterator();
                String colorTag = null;

                int cellIdx = 0; // cell index for retrieving column names
                while (cellIterator.hasNext()) {
                    Cell currentCell = cellIterator.next();

                    if (rowCount == 0) { // First row contains column names
                        columnNames.add(currentCell.getStringCellValue());
                        continue;
                    }

                    if (cellIdx >= columnNames.size() || rowCount == 1) {
                        break;
                    }

                    if (cellIdx == 0 && currentCell.getCellType() == CellType.BLANK){
                        break;
                    }

                    if (currentCell instanceof XSSFCell) {
                        XSSFCell xssfCell = (XSSFCell) currentCell;
                        XSSFColor fillColor = xssfCell.getCellStyle().getFillForegroundColorColor();

                        if (fillColor != null) {
                            String colorStr = "";

                            // Handle RGB color
                            if (fillColor.isRGB()) {
                                byte[] rgb = fillColor.getRGB();
                                colorStr = String.format("#%02X%02X%02X", rgb[0], rgb[1], rgb[2]);
                                switch (colorStr) {
                                    case "#FBBC04":
                                        colorTag = "iab API";
                                        break;
                                    case "#EA4335":
                                        colorTag = "None exists";
                                        break;
                                }
                            }
                            else {
                                // Print out unhandled color types
                                System.out.println("Unhandled color type: " + fillColor.toString());
                            }

                            System.out.println("Fill color of cell " + currentCell.getAddress() + ": " + colorTag);
                        }
                    }

                    String columnName = columnNames.get(cellIdx);

                    System.out.print(columnName + ": "); // Print column name before cell value

                    // Get cell data based on cell type
                    switch (currentCell.getCellType()) {
                        case STRING:
//                            System.out.print(currentCell.getStringCellValue() + " -- ");
                            if (columnName.equals("gdpr") || columnName.equals("US state-level privacy laws (CCPA, etc.)") || columnName.equals("coppa")){
                                parseACellStr(currentCell.getStringCellValue());
                            }
                            break;
                        default:
                            System.out.print("Unknown Type -- " + currentCell.getCellType());
                            break;
                    }
                    cellIdx++; // Increment cell index for next iteration
                }
                System.out.println("------------------------------------------------------------------------------");
                rowCount++;
            }
            workbook.close();  // Don't forget to close the workbook
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
