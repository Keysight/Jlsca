package jlsca;

import com.sun.jna.Platform;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;

import javax.swing.AbstractButton;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.ButtonModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;

import com.riscure.signalanalysis.Module;
import com.riscure.signalanalysis.ModuleInChain;
import com.riscure.signalanalysis.ProgressInterface;
import com.riscure.signalanalysis.Trace;
import com.riscure.signalanalysis.TraceSet;
import com.riscure.signalanalysis.operations.DataOperationException;

/**
 * Wrapper to call Jlsca from Inspector. Make sure the julia executable is in your path, or fail!
 *
 * @author Cees-Bart Breunesse <ceesb@riscure.com>
 *
 */
public class Jlsca4InspectorModule extends Module implements ModuleInChain {
  private static final long serialVersionUID = 1L;

  boolean running = false;

  Jlsca4InspectorPanel panel;
  Process p;
  OutputStream toJlscaStream;
  byte[] dataBytes;
  String kksCsvFilename;

  static void log(Object o) {
    System.err.println(o);
  }

  @Override
  protected void initModule() {
    moduleTitle = "Jlsca4Inspector";
    moduleDescription = "Conditional averaging and more for DES & AES";
    moduleVersion = "0.1";
    panel = new Jlsca4InspectorPanel(this);
    panel.init();
  }

  @Override
  public void setDialogValues() {
    panel.setDialogValues();
    super.setDialogValues();
  }

  @Override
  public void getDialogValues() {
    panel.getDialogValues();
    super.getDialogValues();
  }


  @Override
  public int init(Trace t, ProgressInterface pi, int nt, int sft, int snt, int sfs, int sns)
      throws DataOperationException {
    dataBytes = t.getData().clone();

    TraceSet ts = t.getTraceSet();
    if(ts != null) {
      kksCsvFilename = ts.getName() + ".";
    }
    else {
      kksCsvFilename = workPath + File.separator;
    }

    DateFormat df = new SimpleDateFormat("yyyy-mm-dd_HH:mm");
    Date dateobj = new Date();
    kksCsvFilename += "KKA_" + df.format(dateobj) + ".csv";

    return super.init(t, pi, nt, sft, snt, sfs, sns);
  }

  @Override
  protected JPanel initDialog() {
    return panel;
  }

  static byte[] asBytes(int i) {
    return asBytes(i, 4);
  }

  static byte[] asBytes(int i, int s) {
    byte[] bytes  = new byte[s];

    for(int j=0; j<s; j++) {
      bytes[j] = (byte)(i >> (j * 8));
    }

    return bytes;
  }

  void startJlscaProcess(String parameters, int nrOfSamples) throws IOException {
    String expr = String.format("using Jlsca.Sca, Jlsca.Trs; %s; trs = InspectorTrace(%s); setPostProcessor(trs, CondAvg()); sca(trs, params, 1, length(trs))", parameters, Platform.isWindows() ? "\\\"-\\\"" : "\"-\"");
    log("Jlsca params: " + expr);
    ProcessBuilder pb = new ProcessBuilder("julia", "-e", expr);

    p = pb.start();
    toJlscaStream = new BufferedOutputStream(p.getOutputStream(), nrOfSamples*4);
    new Thread(new Forwarder(p.getInputStream(), System.out)).start();
    new Thread(new Forwarder(p.getErrorStream(), System.err)).start();
  }

  @Override
  public Trace process(Trace t) throws DataOperationException {
    try {
      if(!running) {
        running = true;

        startJlscaProcess(panel.toJlscParameters(), t.getNumberOfSamples());

        // Jlsca eats Inspector traces, but since Inspector cannot write TraceSets to
        // a stream, we have to do it ourselves:

        // number of samples
        toJlscaStream.write(0x42);
        toJlscaStream.write(0x04);
        toJlscaStream.write(asBytes(t.getNumberOfSamples()));

        // sample coding is floats
        toJlscaStream.write(0x43);
        toJlscaStream.write(0x01);
        toJlscaStream.write(0x14);

        // number of data bytes
        toJlscaStream.write(0x44);
        toJlscaStream.write(0x02);
        byte [] data = t.getData();
        toJlscaStream.write(asBytes(data != null ? data.length : 0, 2));

        // magic end of header marker
        toJlscaStream.write(0x5f);
        toJlscaStream.write(0x00);

      }

      // push the data
      toJlscaStream.write(t.getData());

      float[] samples = t.getSample();

      // push samples
      for (int i=0; i<samples.length; i++) {
        int sample = Float.floatToIntBits(samples[i]);
        for(int j=0; j<4; j++) {
          toJlscaStream.write(sample >> (j * 8));
        }
      }

    } catch (IOException e) {
      running = false;
      throw(new DataOperationException(e));
    }

    return null;
  }

  @Override
  public void finishProcess() throws DataOperationException {
    if(running) {
      running = false;
      try {
        toJlscaStream.flush();
        toJlscaStream.close();
        p.waitFor();
      } catch (IOException e) {
        throw(new DataOperationException(e));
      } catch (InterruptedException e) {
        throw(new DataOperationException(e));
      }
    }
  }

  static class Forwarder implements Runnable {
    InputStream input;
    PrintStream output;

    Forwarder(InputStream input, PrintStream output) {
      this.input = input;
      this.output = output;
    }

    @Override
    public void run() {
      BufferedReader reader = new BufferedReader(new InputStreamReader(input));
      String line;
      try {
        while ((line = reader.readLine()) != null) {
          output.println(line);
        }
      } catch (IOException e) {
        throw(new DataOperationException(e));
      }
    }

  }


  static class Jlsca4InspectorPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    Jlsca4InspectorModule module;

    JTextField knownkeyField;
    JTextField knownkeyOffsetInTraceField;
    JTextField updateIntervalField;
    JTextField phaseInputTextField;
    JTextField dataOffsetField;

    JCheckBox xorCheckBox;

    DefaultComboBoxModel<String> modeModel = new DefaultComboBoxModel<>(AES_modes_dec);
    DefaultComboBoxModel<String> attackModel = new DefaultComboBoxModel<>(AES128_chooseninput_attackables);
    DefaultComboBoxModel<String> leakagesModel = new DefaultComboBoxModel<>(CPA_leakages);
    DefaultComboBoxModel<String> keybytesModel = new DefaultComboBoxModel<>(SIXTEEN_KBs);
    DefaultComboBoxModel<String> phaseModel = new DefaultComboBoxModel<>();
    JComboBox<String> modeModelComboBox = new JComboBox<String>();
    JComboBox<String> attackModelComboBox = new JComboBox<String>();
    JComboBox<String> phaseModelBimbobox = new JComboBox<String>();

    ButtonGroup encOrDecGroup = new ButtonGroup();
    ButtonGroup algoGroup = new ButtonGroup();
    ButtonGroup directionGroup = new ButtonGroup();
    ButtonGroup analysisGroup = new ButtonGroup();

    int previouslySuggestedDataOffset = 0;

    static String DES = "DES";
    static String AES = "AES";
    static String encrypt = "encrypt";
    static String decrypt = "decrypt";

    static String AES128 = "AES128";
    static String AES192 = "AES192";
    static String AES192_EQINV = "AES192 (eq inv)";
    static String AES256 = "AES256";
    static String AES256_EQINV = "AES256 (eq inv)";

    static String ONEDES = "DES";
    static String TDES1 = "TDES1";
    static String TDES2 = "TDES2";
    static String TDES3 = "TDES3";

    static String SND_TO_LAST_RND = "2nd to last round";
    static String LAST_RND = "Last round";

    static String FIRST_RND = "First round";
    static String SECOND_RND = "Second round";

    static String LAST_DES = "DES3: ";
    static String MIDDLE_DES = "DES2: ";
    static String FIRST_DES = "DES1: ";

    static String[] DES_OR_AESMORETHAN128_phases_fwd = { FIRST_RND, SECOND_RND };
    static String[] DES_AESMORETHAN128_phases_bwd = { LAST_RND, SND_TO_LAST_RND };
    static String[] TDES2_phases_fwd = {FIRST_DES + FIRST_RND, FIRST_DES + SECOND_RND, MIDDLE_DES + FIRST_RND, MIDDLE_DES + SECOND_RND };
    static String[] TDES3_phases_fwd = {FIRST_DES + FIRST_RND, FIRST_DES + SECOND_RND, MIDDLE_DES + FIRST_RND, MIDDLE_DES + SECOND_RND,  LAST_DES + FIRST_RND, LAST_DES + SECOND_RND };
    static String[] TDES2_phases_bwd = {LAST_DES + LAST_RND, LAST_DES + SND_TO_LAST_RND, MIDDLE_DES + LAST_RND, MIDDLE_DES + SND_TO_LAST_RND };
    static String[] TDES3_phases_bwd = {LAST_DES + LAST_RND, LAST_DES + SND_TO_LAST_RND, MIDDLE_DES + LAST_RND, MIDDLE_DES + SND_TO_LAST_RND,  FIRST_DES + LAST_RND, FIRST_DES + SND_TO_LAST_RND };
    static String[] AES128_MC_phases = {"Kb 1,5,9,13", "Kb 2,6,10,14", "Kb 3,7,11,15", "Kb 4,8,12,16" };

    static String FORWARD = "forward";
    static String BACKWARD = "backward";


    static String[] AES_modes_enc = { AES128, AES192, AES256 };
    static String[] AES_modes_dec = { AES128, AES192, AES256, AES192_EQINV, AES256_EQINV };
    static String[] DES_modes = { ONEDES, TDES2, TDES3 };

    static String MC = "MixColumn";
    static String SB = "Sbox";
    static String RO = "Roundout";

    static String[] AES_attackables = { SB };
    static String[] AES128_chooseninput_attackables = { SB, MC };
    static String[] DES_attackables = { RO, SB };

    static String BIT0 = "Bit 0";
    static String ALLBITS = "All bits";
    static String HW = "HW";

    static String SINGLEBITMODEL = "8 bit";

    static String[] CPA_AES128_chooseninput_leakages = {ALLBITS, BIT0 };
    static String[] CPA_leakages = {ALLBITS, HW, BIT0 };

    static String[] LRA_models = {SINGLEBITMODEL};

    static String CPA = "CPA";
    static String LRA = "LRA";

    static String ALLBYTES = "All bytes";
    static String[] EIGHT_KBs = { ALLBYTES, "1", "2", "3", "4", "5", "6", "7", "8" };
    static String[] SIXTEEN_KBs = { ALLBYTES, "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16" };


    static int kkLength(String alg) {
      if(alg.equals(ONEDES) || alg.equals(TDES1)) {
        return 8;
      }
      if(alg.equals(AES128) || alg.equals(TDES2)) {
        return 16;
      }
      if(alg.equals(AES192) || alg.equals(AES192_EQINV) || alg.equals(TDES3)) {
        return 24;
      }
      if(alg.equals(AES256) || alg.equals(AES256_EQINV)) {
        return 32;
      }

      throw new RuntimeException("WUT " + alg + "?!");
    }

    static String toString(byte[] input) {
      return toString(input, 0, input.length);
    }

    static String toString(byte[] input, int offset, int length) {
      String s = "";
      for(int i=0; i<length; i++) {
        s += String.format("%02x", input[offset+i]);
      }
      return s;
    }

    /**
     * Based on the heuristics BinaryDecoder shakes out of its sleeves.
     *
     * 1. Order is Input; Output
     * 2. Input; Output is always at the end
     * 3. If there's not enough data for Input; Output, then we assume whatever data is needed is at the end
     *
     * @return suggested (0-based) offset of the data in a trace (input or output, depending on the kind of attack)
     */
    int suggestedDataOffset() {
      int dataOffset = 0;

      int blockSize = algoGroup.getSelection().getActionCommand() == AES ? 16 : 8;
      int dataBytesLength = module.dataBytes.length;

//      log("dataBytes: " + dataBytesLength);
//      log("blockSize: " + blockSize);

      if(dataBytesLength >= 2 * blockSize) {
        if(directionGroup.getSelection().getActionCommand() == FORWARD) {
          dataOffset = dataBytesLength - 2 * blockSize;
        }
        else {
          dataOffset = dataBytesLength - blockSize;
        }
      }
      else {
        dataOffset = dataBytesLength - blockSize;
      }

      return dataOffset;
    }

    static void setModel(DefaultComboBoxModel<String> model, String[] content) {
      int prevIdx = model.getIndexOf(model.getSelectedItem());

      model.removeAllElements();
      for (String s : content) {
        model.addElement(s);
      }

      if(prevIdx < model.getSize() && prevIdx >= 0) {
        model.setSelectedItem(model.getElementAt(prevIdx));
      }
      else {
        model.setSelectedItem(model.getElementAt(0));
      }
    }

    static void log(Object o) {
      System.err.println(o);
    }

    void updateAttackPanel() {
      if(algoGroup.getSelection().getActionCommand() == AES) {
        if(modeModel.getSelectedItem() == AES128 && directionGroup.getSelection().getActionCommand() == FORWARD) {
          setModel(attackModel, AES128_chooseninput_attackables);
        }
        else {
          setModel(attackModel, AES_attackables);
        }
      }
      else {
        setModel(attackModel, DES_attackables);
      }
    }

    void updateKnownKeypanel() {
      String s = knownkeyField.getText();
      boolean isHex = s.matches("-?[0-9a-fA-F]+");
      boolean isCorrectLength = s.length() == 2*kkLength((String)modeModel.getSelectedItem());

      if(s.length() > 0) {
        knownkeyOffsetInTraceField.setEnabled(false);
      }
      else {
        knownkeyOffsetInTraceField.setEnabled(true);
      }

      if(s.length() < 2) {
        knownkeyField.setBackground(Color.WHITE);
      }
      else if(isHex && isCorrectLength) {
        knownkeyField.setBackground(Color.GREEN);
      }
      else if(!isHex) {
        knownkeyField.setBackground(Color.RED);
      }
      else {
        knownkeyField.setBackground(Color.ORANGE);
      }


    }

    void updateLeakagesPanel() {
      if(analysisGroup.getSelection().getActionCommand() == LRA) {
        setModel(leakagesModel, LRA_models);
      }
      else if(attackModel.getSelectedItem() == MC) {
        setModel(leakagesModel, CPA_AES128_chooseninput_leakages);
      }
      else {
        setModel(leakagesModel, CPA_leakages);
      }
    }

    void updatePhasePanel() {
      if((algoGroup.getSelection().getActionCommand() == AES && modeModel.getSelectedItem() != AES128) || modeModel.getSelectedItem() == ONEDES) {
        phaseModelBimbobox.setEnabled(true);
        phaseInputTextField.setEnabled(true);
        if(directionGroup.getSelection().getActionCommand() == FORWARD) {
          setModel(phaseModel, DES_OR_AESMORETHAN128_phases_fwd);
        }
        else {
          setModel(phaseModel, DES_AESMORETHAN128_phases_bwd);
        }
      }
      else if(modeModel.getSelectedItem() == TDES2) {
        phaseModelBimbobox.setEnabled(true);
        phaseInputTextField.setEnabled(true);
        if(directionGroup.getSelection().getActionCommand() == FORWARD) {
          setModel(phaseModel, TDES2_phases_fwd);
        }
        else {
          setModel(phaseModel, TDES2_phases_bwd);
        }
      }
      else if(modeModel.getSelectedItem() == TDES3) {
        phaseModelBimbobox.setEnabled(true);
        phaseInputTextField.setEnabled(true);
        if(directionGroup.getSelection().getActionCommand() == FORWARD) {
          setModel(phaseModel, TDES3_phases_fwd);
        }
        else {
          setModel(phaseModel, TDES3_phases_bwd);
        }
      }
      else if (algoGroup.getSelection().getActionCommand() == AES && modeModel.getSelectedItem() == AES128 && attackModel.getSelectedItem() == MC) {
        phaseModelBimbobox.setEnabled(true);
        phaseInputTextField.setEnabled(true);
        setModel(phaseModel, AES128_MC_phases);
      }
      else {
        phaseModel.removeAllElements();
        phaseModelBimbobox.setEnabled(false);
        phaseInputTextField.setEnabled(false);
      }

    }


    void updateDataOffsetFieldConditional() {
      // do not update this field if user entered something before we did not suggested ourselves
      if(Integer.parseInt(dataOffsetField.getText()) == previouslySuggestedDataOffset) {
        updateDataOffsetField();
      }
    }

    void updateDataOffsetField() {
      SwingUtilities.invokeLater(new Runnable() {
        @Override
        public void run() {
          dataOffsetField.setText(Integer.toString(previouslySuggestedDataOffset = suggestedDataOffset()));
        }
      });
    }

    void updateKeybytesPanel() {

      if(algoGroup.getSelection().getActionCommand() == DES) {
        setModel(keybytesModel, EIGHT_KBs);
      }
      else {
        setModel(keybytesModel, SIXTEEN_KBs);
      }
    }

    static String ALGO = "algo";
    static String ENCDEC = "encryptordecrypt";
    static String MODE = "mode";
    static String KNOWNKEYVALUE = "knownkeyvalue";
    static String KNOWNKEYOFFSET = "knownkeyoffset";
    static String DIRECTION = "direction";
    static String DATAOFFSET = "dataoffset";
    static String ATTACKABLE = "attackable";
    static String XOR = "xor";
    static String PHASE = "phase";
    static String PHASEINPUT = "phaseinput";
    static String UPDATEINTERVAL = "updateinterval";
    static String ANALYSIS = "analysis";
    static String LEAKAGE = "leakage";
    static String KEYBYTES = "keybytes";


    void init() {
      module.set(ALGO, AES);
      module.set(ENCDEC, encrypt);
      module.set(MODE, AES128);
      module.set(KNOWNKEYVALUE, "");
      module.set(KNOWNKEYOFFSET, "");
      module.set(DIRECTION, FORWARD);
      module.set(DATAOFFSET, "0");
      module.set(ATTACKABLE, SB);
      module.set(XOR, false);
      module.set(PHASE, "");
      module.set(PHASEINPUT, "");
      module.set(UPDATEINTERVAL, "0");
      module.set(ANALYSIS, CPA);
      module.set(LEAKAGE, ALLBITS);
      module.set(KEYBYTES, ALLBYTES);

    }

    void setDialogValues() {
      algoGroup.setSelected(actionCommandToButtonModel(algoGroup, (String)module.get(ALGO)), true);
      encOrDecGroup.setSelected(actionCommandToButtonModel(encOrDecGroup, (String)module.get(ENCDEC)), true);
      modeModel.setSelectedItem((String)module.get(MODE));
      knownkeyField.setText((String)module.get(KNOWNKEYVALUE));
      knownkeyOffsetInTraceField.setText((String)module.get(KNOWNKEYOFFSET));
      directionGroup.setSelected(actionCommandToButtonModel(directionGroup, (String)module.get(DIRECTION)), true);
      dataOffsetField.setText((String)module.get(DATAOFFSET));
      attackModel.setSelectedItem((String)module.get(ATTACKABLE));
      xorCheckBox.setSelected((Boolean)module.get(XOR));
      phaseModel.setSelectedItem((String)module.get(PHASE));
      phaseInputTextField.setText((String)module.phaseInput);
      updateIntervalField.setText((String)module.get(UPDATEINTERVAL));
      analysisGroup.setSelected(actionCommandToButtonModel(analysisGroup, (String)module.get(ANALYSIS)), true);
      leakagesModel.setSelectedItem((String)module.get(LEAKAGE));
      keybytesModel.setSelectedItem((String)module.get(KEYBYTES));
    }

    void getDialogValues() {
      module.set(ALGO, algoGroup.getSelection().getActionCommand());
      module.set(ENCDEC, encOrDecGroup.getSelection().getActionCommand());
      module.set(MODE, (String)modeModel.getSelectedItem());
      module.set(KNOWNKEYVALUE, knownkeyField.getText());
      module.set(KNOWNKEYOFFSET, knownkeyOffsetInTraceField.getText());
      module.set(DIRECTION, directionGroup.getSelection().getActionCommand());
      module.set(DATAOFFSET, dataOffsetField.getText());
      module.set(ATTACKABLE, (String)attackModel.getSelectedItem());
      module.set(XOR, xorCheckBox.isSelected());
      module.set(PHASE, phaseModelBimbobox.isEnabled() ? phaseModel.getSelectedItem() : "");
      module.set(PHASEINPUT, phaseInputTextField.getText());
      module.set(UPDATEINTERVAL, updateIntervalField.getText());
      module.set(ANALYSIS, analysisGroup.getSelection().getActionCommand());
      module.set(LEAKAGE, leakagesModel.getSelectedItem());
      module.set(KEYBYTES, keybytesModel.getSelectedItem());
    }

    static ButtonModel actionCommandToButtonModel(ButtonGroup bg, String actionCommand) {
      Enumeration<AbstractButton> buttons = bg.getElements();

      while (buttons.hasMoreElements()) {
        AbstractButton b = buttons.nextElement();
        ButtonModel model = b.getModel();
        if(model.getActionCommand() == actionCommand) {
          return model;
        }

      }

      return null;
    }

    /**
     * Create the panel.
     */
    public Jlsca4InspectorPanel(Jlsca4InspectorModule m) {
      module = m;

      ActionListener directionListener = new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          updateAttackPanel();
          updatePhasePanel();
          updateDataOffsetFieldConditional();
        }
      };

      ItemListener modeItemListener = new ItemListener() {

        @Override
        public void itemStateChanged(ItemEvent e) {
          if(e.getStateChange() == ItemEvent.SELECTED) {
            updateKnownKeypanel();
            updateAttackPanel();
            updatePhasePanel();
            updateKeybytesPanel();
          }
        }
      };

      ActionListener modeListener = new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          if(algoGroup.getSelection().getActionCommand() == AES) {
            if(encOrDecGroup.getSelection().getActionCommand() == encrypt) {
              setModel(modeModel, AES_modes_enc);
            }
            else {
              setModel(modeModel, AES_modes_dec);
            }
          }
          else if(algoGroup.getSelection().getActionCommand() == DES) {
            setModel(modeModel, DES_modes);
          }
          updateDataOffsetFieldConditional();      }
      };


      CaretListener knownKeyListener = new CaretListener() {

        @Override
        public void  caretUpdate(CaretEvent e) {
          updateKnownKeypanel();
        }
      };

      CaretListener offsetListener = new CaretListener() {

        @Override
        public void  caretUpdate(CaretEvent e) {
          JTextField jeff = ((JTextField)e.getSource());
          if(jeff.getText().length() > 0) {
            knownkeyField.setEnabled(false);
          }
          else {
            knownkeyField.setEnabled(true);
          }
        }
      };

      FocusListener dataOffsetFocusListener = new FocusListener() {

        @Override
        public void focusLost(FocusEvent e) {
          JTextField jeff = ((JTextField)e.getSource());
          if(jeff.getText().length() == 0) {
            updateDataOffsetField();
          }
        }

        @Override
        public void focusGained(FocusEvent e) {
          // don't care
        }
      };

      ActionListener attackModelListener = new ActionListener() {

        @Override
        public void actionPerformed(ActionEvent e) {
          updateLeakagesPanel();
          updatePhasePanel();
        }

      };

      ActionListener phaseModelListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
          if(phaseModel.getIndexOf(phaseModel.getSelectedItem()) == 0) {
            phaseInputTextField.setEnabled(false);
          }
          else {
            phaseInputTextField.setEnabled(true);
          }
        }
      };

      setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

      JPanel panel = new JPanel();
      panel.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "Target", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(51, 51, 51)));
      add(panel);
      panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

      JPanel panel_2 = new JPanel();
      panel.add(panel_2);

      JRadioButton radioButton = new JRadioButton(DES);
      radioButton.setActionCommand(DES);
      algoGroup.add(radioButton);
      panel_2.add(radioButton);
      radioButton.addActionListener(modeListener);

      JRadioButton radioButton_1 = new JRadioButton(AES);
      radioButton_1.setActionCommand(AES);
      algoGroup.add(radioButton_1);
      radioButton_1.setSelected(true);
      panel_2.add(radioButton_1);
      radioButton_1.addActionListener(modeListener);


      JRadioButton radioButton_2 = new JRadioButton(encrypt);
      radioButton_2.setActionCommand(encrypt);
      encOrDecGroup.add(radioButton_2);
      radioButton_2.setSelected(true);
      panel_2.add(radioButton_2);
      radioButton_2.addActionListener(modeListener);

      JRadioButton radioButton_3 = new JRadioButton(decrypt);
      radioButton_3.setActionCommand(decrypt);
      encOrDecGroup.add(radioButton_3);
      panel_2.add(radioButton_3);
      radioButton_3.addActionListener(modeListener);

      modeModelComboBox.setModel(modeModel);
      modeModelComboBox.setPrototypeDisplayValue(AES256_EQINV);
      panel_2.add(modeModelComboBox);
      modeModelComboBox.addItemListener(modeItemListener);

      JPanel panel_3 = new JPanel();
      panel.add(panel_3);

      JLabel lblNewLabel = new JLabel("Known key");
      panel_3.add(lblNewLabel);

      knownkeyField = new JTextField();
      panel_3.add(knownkeyField);
      knownkeyField.setColumns(20);
      knownkeyField.addCaretListener(knownKeyListener);

      JLabel lblNewLabel_1 = new JLabel("or offset in trace");
      panel_3.add(lblNewLabel_1);

      knownkeyOffsetInTraceField = new JTextField();
      panel_3.add(knownkeyOffsetInTraceField);
      knownkeyOffsetInTraceField.setColumns(2);
      knownkeyOffsetInTraceField.addCaretListener(offsetListener);

      JPanel panel_1 = new JPanel();
      panel_1.setBorder(new TitledBorder(null, "Attack", TitledBorder.LEADING, TitledBorder.TOP, null, null));
      add(panel_1);
      panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.Y_AXIS));

      JPanel panel_5 = new JPanel();
      panel_1.add(panel_5);

      JRadioButton rdbtnForward = new JRadioButton(FORWARD);
      rdbtnForward.setActionCommand(FORWARD);
      rdbtnForward.setSelected(true);
      rdbtnForward.addActionListener(directionListener);
      panel_5.add(rdbtnForward);
      directionGroup.add(rdbtnForward);

      JRadioButton rdbtnBackward = new JRadioButton(BACKWARD);
      rdbtnBackward.setActionCommand(BACKWARD);
      rdbtnBackward.addActionListener(directionListener);
      panel_5.add(rdbtnBackward);
      directionGroup.add(rdbtnBackward);

      JSeparator separator = new JSeparator();
      panel_5.add(separator);

      JLabel label = new JLabel("Data offset in trace");
      panel_5.add(label);

      dataOffsetField = new JTextField();
      panel_5.add(dataOffsetField);
      dataOffsetField.setText(Integer.toString(0));
      dataOffsetField.setColumns(10);
      dataOffsetField.addFocusListener(dataOffsetFocusListener);

      JPanel panel_4 = new JPanel();
      panel_1.add(panel_4);

      panel_4.add(attackModelComboBox);
      attackModelComboBox.setModel(attackModel);
      attackModelComboBox.setPrototypeDisplayValue(RO);
      attackModelComboBox.addActionListener(attackModelListener);

      xorCheckBox = new JCheckBox("xor");
      panel_4.add(xorCheckBox);

      JPanel panel_7 = new JPanel();
      panel_1.add(panel_7);
      panel_7.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

      JLabel lblPhase = new JLabel("Phase");
      panel_7.add(lblPhase);

      phaseModelBimbobox.setModel(phaseModel);
      phaseModelBimbobox.setPrototypeDisplayValue(LAST_DES + SND_TO_LAST_RND);
      phaseModelBimbobox.addActionListener(phaseModelListener);
      phaseModelBimbobox.setEnabled(false);
      panel_7.add(phaseModelBimbobox);

      JLabel lblPhaseInput = new JLabel("Phase input");
      panel_7.add(lblPhaseInput);

      phaseInputTextField = new JTextField();
      panel_7.add(phaseInputTextField);
      phaseInputTextField.setColumns(10);
      phaseInputTextField.setEnabled(false);

      JPanel panel_6 = new JPanel();
      panel_1.add(panel_6);

      JLabel lblUpdateInterval = new JLabel("Update interval");
      panel_6.add(lblUpdateInterval);

      updateIntervalField = new JTextField();
      updateIntervalField.setText("0");
      panel_6.add(updateIntervalField);
      updateIntervalField.setColumns(10);

      JPanel panel_8 = new JPanel();
      panel_8.setBorder(new TitledBorder(null, "Analysis", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(51, 51, 51)));
      add(panel_8);

      JRadioButton rdbtnCpa = new JRadioButton(CPA);
      rdbtnCpa.setActionCommand(CPA);
      rdbtnCpa.setSelected(true);
      rdbtnCpa.addActionListener(attackModelListener);
      panel_8.add(rdbtnCpa);
      analysisGroup.add(rdbtnCpa);

      JRadioButton rdbtnLra = new JRadioButton(LRA);
      rdbtnLra.setActionCommand(LRA);
      rdbtnLra.addActionListener(attackModelListener);
      panel_8.add(rdbtnLra);
      analysisGroup.add(rdbtnLra);


      JComboBox<String> comboBox_3 = new JComboBox<String>();
      comboBox_3.setModel(leakagesModel);
      comboBox_3.setPrototypeDisplayValue(ALLBITS);
      panel_8.add(comboBox_3);


      JComboBox<String> comboBox_4 = new JComboBox<String>();
      comboBox_4.setModel(keybytesModel);
      comboBox_4.setPrototypeDisplayValue(ALLBYTES);
      panel_8.add(comboBox_4);

    }

    /**
     * @return a String containing an executable Julia expression that creates a "params" object and stores the attack parameters in that object.
     */
    String toJlscParameters() {
      String s = "";

      if(algoGroup.getSelection().getActionCommand() == AES) {
        if(attackModel.getSelectedItem() == SB) {
          s += "params = Sca.AesSboxAttack(); ";
        }
        else if(attackModel.getSelectedItem() == MC) {
          s += "params = Sca.AesMCAttack(); ";
        }

        if(encOrDecGroup.getSelection().getActionCommand() == encrypt) {
          s += "params.mode = Sca.CIPHER; ";
        }
        else if(encOrDecGroup.getSelection().getActionCommand() == decrypt) {
          if(modeModel.getSelectedItem().toString().endsWith("inv)")) {
            s += "params.mode = Sca.EQINVCIPHER; ";
          }
          else {
            s += "params.mode = Sca.INVCIPHER; ";
          }
        }

        s += String.format("params.keyLength = %d;", kkLength(((String)modeModel.getSelectedItem())));
      }
      else if(algoGroup.getSelection().getActionCommand() == DES) {
        s += "params = Sca.DesSboxAttack(); ";

        s += String.format("params.encrypt = %b; ",  encOrDecGroup.getSelection().getActionCommand() == encrypt);
        s += String.format("params.mode = Sca.%s; ", modeModel.getSelectedItem());
        s += String.format("params.targetType = Sca.%s; ", ((String)attackModel.getSelectedItem()).toUpperCase());

      }

      s += String.format("params.direction = Sca.%s; ", directionGroup.getSelection().getActionCommand().toUpperCase());
      s += String.format("params.dataOffset = %d; ", Integer.parseInt(dataOffsetField.getText()) + 1);
      s += String.format("params.xor = %s; ", Boolean.toString(xorCheckBox.isSelected()));

      String knownkey = null;
      if(knownkeyOffsetInTraceField.isEditable() && knownkeyOffsetInTraceField.getText().length() > 0) {
        knownkey = toString(module.dataBytes, Integer.parseInt(knownkeyOffsetInTraceField.getText()), kkLength((String)modeModel.getSelectedItem()));

      }
      else if(knownkeyField.isEditable() && knownkeyField.getText().length() > 0) {
        knownkey = knownkeyField.getText();
      }

      if(knownkey != null) {
          if(Platform.isWindows()) {
        	  s += String.format("params.knownKey = Nullable(hex2bytes(\\\"%s\\\")); ", knownkey);
          } else {
        	  s += String.format("params.knownKey = Nullable(hex2bytes(\"%s\")); ", knownkey);
          }
      }

      int updateInterval = Integer.parseInt(updateIntervalField.getText());
      if(updateInterval > 1) {
        s += String.format("params.updateInterval = %d; ", updateInterval);
      }

      if(analysisGroup.getSelection().getActionCommand() == CPA) {
        s += "params.analysis = Sca.CPA(); ";
        if(leakagesModel.getSelectedItem() == ALLBITS) {
          int bits = 0;
          if(algoGroup.getSelection().getActionCommand() == AES) {
            bits = 7;
            if(attackModel.getSelectedItem() == MC) {
              bits = 31;
            }
          }
          else {
            bits = 3;
          }
          s += String.format("params.analysis.leakages = [Bit(i) for i in 0:%d ]; ", bits);
        }
        else if(leakagesModel.getSelectedItem() == BIT0) {
          s += String.format("params.analysis.leakages = [Bit(0)]; ", updateInterval);
        }
        else if(leakagesModel.getSelectedItem() == HW) {
          s += String.format("params.analysis.leakages = [HW()]; ", updateInterval);
        }
      }
      else if(analysisGroup.getSelection().getActionCommand() == LRA) {
        s += "params.analysis = Sca.LRA(); ";
        if(leakagesModel.getSelectedItem() == SINGLEBITMODEL)
          s += String.format("params.analysis.basisModel = Sca.basisModelSingleBits; ", updateInterval);
      }

      int phase = 0;
      String phaseInput = null;
      if(phaseModelBimbobox.isEnabled()) {
        phase = phaseModel.getIndexOf(phaseModel.getSelectedItem());
      }
      if(phaseInputTextField.isEditable() && phaseInputTextField.getText().length() > 0) {
        phaseInput = phaseInputTextField.getText();
      }
      s += String.format("params.phases = [Sca.PHASE%d]; ", phase+1);

      if(phaseInput != null) {
          if(Platform.isWindows()) {
        	  s += String.format("params.phaseInput = Nullable(hex2bytes(\\\"%s\\\")); ", phaseInput);
          } else {
        	  s += String.format("params.phaseInput = Nullable(hex2bytes(\"%s\")); ", phaseInput);
          }
      }

      if(keybytesModel.getSelectedItem() == ALLBYTES) {
        s += String.format("params.keyByteOffsets = collect(1:%d); ", algoGroup.getSelection().getActionCommand() == AES ? 16 : 8);
      }
      else {
        s += String.format("params.keyByteOffsets = [%d]; ", keybytesModel.getIndexOf(keybytesModel.getSelectedItem()));
      }

      if(Platform.isWindows()) {
    	  s += String.format("params.outputkka = Nullable(\\\"%s\\\"); ", module.kksCsvFilename.replace("\\", "/"));
      }
      else {
    	  s += String.format("params.outputkka = Nullable(\"%s\"); ", module.kksCsvFilename);
      }

      return s;
    }

  }

}
