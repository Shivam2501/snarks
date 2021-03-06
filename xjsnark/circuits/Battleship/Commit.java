package xjsnark.battleship;

/*Generated by MPS */

import backend.auxTypes.StructDefinition;
import backend.auxTypes.UnsignedInteger;
import java.math.BigInteger;
import backend.structure.CircuitGenerator;
import java.util.ArrayList;
import backend.auxTypes.VariableState;
import backend.auxTypes.IAuxType;

public class Commit extends StructDefinition {


  /*package*/ UnsignedInteger row = new UnsignedInteger(8, new BigInteger("0"));
  /*package*/ UnsignedInteger column = new UnsignedInteger(8, new BigInteger("0"));
  /*package*/ UnsignedInteger ship = new UnsignedInteger(8, new BigInteger("0"));


  public void __makeInput() {

    row = UnsignedInteger.createInput(CircuitGenerator.__getActiveCircuitGenerator(), 8);
    column = UnsignedInteger.createInput(CircuitGenerator.__getActiveCircuitGenerator(), 8);
    ship = UnsignedInteger.createInput(CircuitGenerator.__getActiveCircuitGenerator(), 8);










  }


  public void __makeOutput() {
    UnsignedInteger.makeOutput(CircuitGenerator.__getActiveCircuitGenerator(), row);
    UnsignedInteger.makeOutput(CircuitGenerator.__getActiveCircuitGenerator(), column);
    UnsignedInteger.makeOutput(CircuitGenerator.__getActiveCircuitGenerator(), ship);





  }


  public void __makeWitness() {


    row = UnsignedInteger.createWitness(CircuitGenerator.__getActiveCircuitGenerator(), 8);
    column = UnsignedInteger.createWitness(CircuitGenerator.__getActiveCircuitGenerator(), 8);
    ship = UnsignedInteger.createWitness(CircuitGenerator.__getActiveCircuitGenerator(), 8);










  }


  public void __makeVerifiedWitness() {

    row = UnsignedInteger.createVerifiedWitness(CircuitGenerator.__getActiveCircuitGenerator(), 8);
    column = UnsignedInteger.createVerifiedWitness(CircuitGenerator.__getActiveCircuitGenerator(), 8);
    ship = UnsignedInteger.createVerifiedWitness(CircuitGenerator.__getActiveCircuitGenerator(), 8);











  }

  public void __alignAndPackAll() {

    ArrayList<VariableState> states = new ArrayList();
    states.add(row.getState());
    states.add(column.getState());
    states.add(ship.getState());







    for (VariableState state : states) {
      state.setPackedAhead(true);
      state.setMustBeWithinRange(true);
      state.setConditionallySplittedAndAlignedAhead(true);
    }

  }
  public static Class<?> __getClassRef() {
    return Commit.class;
  }

  public StructDefinition __copy() {
    return null;
  }
  public int[] __getBasicElementsDetails() {
    return null;
  }
  public ArrayList<IAuxType> __getBasicElements() {
    ArrayList<IAuxType> list = new ArrayList();
    list.add(row);
    list.add(column);
    list.add(ship);







    return list;
  }
}
